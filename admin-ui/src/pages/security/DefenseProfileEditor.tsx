import { useState, useCallback, useRef, useEffect, useMemo } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  addEdge,
  reconnectEdge,
  useNodesState,
  useEdgesState,
  type Connection,
  type Edge,
  type Node,
  BackgroundVariant,
  Panel,
  MarkerType,
  type ReactFlowInstance,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import dagre from 'dagre'

import { defenseProfilesApi } from '@/api/client'
import type { DefenseProfile, GraphNode, DefenseType, OperatorType, ActionType, ObservationType, AttackSignatureAttachment } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { useToast } from '@/components/ui/use-toast'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { ArrowLeft, Save, Loader2, AlertTriangle, LayoutGrid, Play, GitBranch, Target } from 'lucide-react'

import { nodeTypes } from '@/components/defense-profile/nodes'
import { NodeToolbox } from '@/components/defense-profile/NodeToolbox'
import { NodeConfigPanel } from '@/components/defense-profile/NodeConfigPanel'
import { SimulateDialog } from '@/components/defense-profile/SimulateDialog'
import { SignaturesTab } from '@/components/defense-profile/SignaturesTab'

// Node data type for this editor
type FlowNodeData = Record<string, unknown>
type FlowNode = Node<FlowNodeData, string>
type FlowEdge = Edge<Record<string, unknown>>

// Edge colors based on target node type
const EDGE_COLORS: {
  action: Record<string, string>
  defense: string
  operator: string
  observation: string
  start: string
  default: string
} = {
  // Action node colors - matches the action's semantic meaning
  action: {
    allow: '#22c55e',    // green-500
    block: '#ef4444',    // red-500
    captcha: '#f59e0b',  // amber-500
    tarpit: '#f97316',   // orange-500
    flag: '#eab308',     // yellow-500
    monitor: '#6b7280',  // gray-500
  },
  // Node type colors (when target is not an action)
  defense: '#3b82f6',    // blue-500
  operator: '#8b5cf6',   // purple-500
  observation: '#10b981', // emerald-500
  start: '#64748b',      // slate-500
  default: '#94a3b8',    // slate-400
}

// Helper to get edge color based on target node
function getEdgeColor(targetId: string, nodes: FlowNode[]): string {
  const targetNode = nodes.find(n => n.id === targetId)
  if (!targetNode) return EDGE_COLORS.default

  switch (targetNode.type) {
    case 'action': {
      const action = targetNode.data.action as string
      return EDGE_COLORS.action[action] || EDGE_COLORS.default
    }
    case 'defense':
      return EDGE_COLORS.defense
    case 'operator':
      return EDGE_COLORS.operator
    case 'observation':
      return EDGE_COLORS.observation
    case 'start':
      return EDGE_COLORS.start
    default:
      return EDGE_COLORS.default
  }
}

// Dagre layout configuration - Top-to-Bottom flow
const NODE_WIDTH = 180
const NODE_HEIGHT = 70

function getLayoutedElements(
  nodes: FlowNode[],
  edges: FlowEdge[],
  direction: 'LR' | 'TB' = 'TB'
): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const dagreGraph = new dagre.graphlib.Graph()
  dagreGraph.setDefaultEdgeLabel(() => ({}))
  // TB: wider horizontal spacing for threshold branch outputs
  dagreGraph.setGraph({ rankdir: direction, nodesep: 80, ranksep: 100 })

  // Add nodes to dagre
  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT })
  })

  // Add edges to dagre
  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target)
  })

  // Run the layout
  dagre.layout(dagreGraph)

  // Apply the computed positions to nodes
  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id)
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - NODE_WIDTH / 2,
        y: nodeWithPosition.y - NODE_HEIGHT / 2,
      },
    }
  })

  return { nodes: layoutedNodes, edges }
}

// Convert API graph format to React Flow format
function graphToFlow(profile: DefenseProfile): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const nodes: FlowNode[] = []
  const edges: FlowEdge[] = []

  // First pass: create all nodes
  for (const node of profile.graph.nodes) {
    const flowNode: FlowNode = {
      id: node.id,
      type: node.type,
      position: node.position || { x: 0, y: 0 },
      data: { ...node } as FlowNodeData,
    }

    // Add type-specific data
    if (node.type === 'defense') {
      flowNode.data.defense = (node as GraphNode & { defense: DefenseType }).defense
    } else if (node.type === 'operator') {
      flowNode.data.operator = (node as GraphNode & { operator: OperatorType }).operator
      flowNode.data.inputs = (node as GraphNode & { inputs?: string[] }).inputs
    } else if (node.type === 'action') {
      flowNode.data.action = (node as GraphNode & { action: ActionType }).action
    } else if (node.type === 'observation') {
      flowNode.data.observation = (node as GraphNode & { observation: ObservationType }).observation
    }

    nodes.push(flowNode)
  }

  // Second pass: create edges with colors based on target node
  for (const node of profile.graph.nodes) {
    if (node.outputs) {
      for (const [sourceHandle, targetId] of Object.entries(node.outputs)) {
        const edgeColor = getEdgeColor(targetId, nodes)
        edges.push({
          id: `${node.id}-${sourceHandle}-${targetId}`,
          source: node.id,
          target: targetId,
          sourceHandle,
          targetHandle: 'input',
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: edgeColor,
          },
          style: {
            strokeWidth: 2,
            stroke: edgeColor,
          },
        })
      }
    }
  }

  return { nodes, edges }
}

// Convert React Flow format back to API graph format
function flowToGraph(nodes: FlowNode[], edges: FlowEdge[]): GraphNode[] {
  const graphNodes: GraphNode[] = []

  for (const node of nodes) {
    // Build outputs from edges
    const outputs: Record<string, string> = {}
    for (const edge of edges) {
      if (edge.source === node.id && edge.sourceHandle) {
        outputs[edge.sourceHandle] = edge.target
      }
    }

    const outputsObj = Object.keys(outputs).length > 0 ? outputs : undefined
    const configObj = node.data.config as Record<string, unknown> | undefined

    // Create type-specific nodes
    if (node.type === 'defense') {
      graphNodes.push({
        id: node.id,
        type: 'defense',
        position: node.position,
        outputs: outputsObj,
        config: configObj,
        defense: node.data.defense as DefenseType,
      } as GraphNode)
    } else if (node.type === 'operator') {
      const inputs = node.data.inputs as string[] | undefined
      graphNodes.push({
        id: node.id,
        type: 'operator',
        position: node.position,
        outputs: outputsObj,
        config: configObj,
        operator: node.data.operator as OperatorType,
        inputs: inputs && inputs.length > 0 ? inputs : undefined,
      } as GraphNode)
    } else if (node.type === 'action') {
      graphNodes.push({
        id: node.id,
        type: 'action',
        position: node.position,
        outputs: outputsObj,
        config: configObj,
        action: node.data.action as ActionType,
      } as GraphNode)
    } else if (node.type === 'observation') {
      graphNodes.push({
        id: node.id,
        type: 'observation',
        position: node.position,
        outputs: outputsObj,
        config: configObj,
        observation: node.data.observation as ObservationType,
      } as GraphNode)
    } else {
      // Start node
      graphNodes.push({
        id: node.id,
        type: 'start',
        position: node.position,
        outputs: outputsObj,
        config: configObj,
      } as GraphNode)
    }
  }

  return graphNodes
}

// Generate unique node ID
let nodeIdCounter = 0
function generateNodeId(type: string): string {
  return `${type}_${Date.now()}_${++nodeIdCounter}`
}

export default function DefenseProfileEditor() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const reactFlowWrapper = useRef<HTMLDivElement>(null)
  const [reactFlowInstance, setReactFlowInstance] = useState<ReactFlowInstance | null>(null)

  const isNew = !id || id === 'new'

  // Active tab state
  const [activeTab, setActiveTab] = useState<'graph' | 'signatures'>('graph')

  // Form state for profile metadata
  const [profileData, setProfileData] = useState({
    id: '',
    name: '',
    description: '',
    priority: 500,
  })

  // Attack signatures attachment state
  const [attackSignatures, setAttackSignatures] = useState<AttackSignatureAttachment | undefined>(undefined)

  // React Flow state with proper typing
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>([])
  const [selectedNode, setSelectedNode] = useState<FlowNode | null>(null)
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false)
  const [showUnsavedDialog, setShowUnsavedDialog] = useState(false)
  const [pendingNavigation, setPendingNavigation] = useState<string | null>(null)
  const [showSimulateDialog, setShowSimulateDialog] = useState(false)

  // Fetch existing profile
  const { data: profileResponse, isLoading } = useQuery({
    queryKey: ['defense-profile', id],
    queryFn: () => defenseProfilesApi.get(id!),
    enabled: !isNew,
  })

  // Initialize from fetched profile or create new
  useEffect(() => {
    if (isNew) {
      // Create default new profile structure
      const defaultNodes: FlowNode[] = [
        {
          id: 'start',
          type: 'start',
          position: { x: 100, y: 200 },
          data: {},
        },
        {
          id: 'action_allow',
          type: 'action',
          position: { x: 400, y: 200 },
          data: { action: 'allow' },
        },
      ]
      const defaultEdges: FlowEdge[] = [
        {
          id: 'start-next-action_allow',
          source: 'start',
          target: 'action_allow',
          sourceHandle: 'next',
          targetHandle: 'input',
          markerEnd: { type: MarkerType.ArrowClosed },
          style: { strokeWidth: 2 },
        },
      ]
      setNodes(defaultNodes)
      setEdges(defaultEdges)
      setHasUnsavedChanges(false)
    } else if (profileResponse?.profile) {
      const profile = profileResponse.profile
      setProfileData({
        id: profile.id,
        name: profile.name,
        description: profile.description || '',
        priority: profile.priority,
      })
      // Initialize attack signatures from profile
      setAttackSignatures(profile.attack_signatures)
      const { nodes: flowNodes, edges: flowEdges } = graphToFlow(profile)

      // Apply auto-layout to loaded profile (Top-to-Bottom)
      const { nodes: layoutedNodes } = getLayoutedElements(flowNodes, flowEdges, 'TB')
      setNodes(layoutedNodes)
      setEdges(flowEdges)
      setHasUnsavedChanges(false)

      // Fit view after layout
      setTimeout(() => {
        reactFlowInstance?.fitView({ padding: 0.2 })
      }, 100)
    }
  }, [isNew, profileResponse, setNodes, setEdges, reactFlowInstance])

  // Recolor edges when nodes change (e.g., when action type is updated)
  useEffect(() => {
    // Skip during initial render or when nodes are empty
    if (nodes.length === 0) return

    setEdges((eds) =>
      eds.map((edge) => {
        const edgeColor = getEdgeColor(edge.target, nodes)
        const currentStroke = edge.style?.stroke
        // Only update if color changed to avoid infinite loops
        if (currentStroke === edgeColor) return edge
        return {
          ...edge,
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: edgeColor,
          },
          style: {
            ...edge.style,
            stroke: edgeColor,
          },
        }
      })
    )
  }, [nodes, setEdges])

  // Track changes - wrap the change handlers
  const handleNodesChange = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (changes: any) => {
      onNodesChange(changes)
      setHasUnsavedChanges(true)
    },
    [onNodesChange]
  )

  const handleEdgesChange = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (changes: any) => {
      onEdgesChange(changes)
      setHasUnsavedChanges(true)
    },
    [onEdgesChange]
  )

  // Handle connections
  const onConnect = useCallback(
    (params: Connection) => {
      const edgeColor = params.target ? getEdgeColor(params.target, nodes) : EDGE_COLORS.default
      setEdges((eds) =>
        addEdge(
          {
            ...params,
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: edgeColor,
            },
            style: {
              strokeWidth: 2,
              stroke: edgeColor,
            },
          },
          eds
        )
      )
      setHasUnsavedChanges(true)
    },
    [setEdges, nodes]
  )

  // Handle edge reconnection (dragging edge to new target)
  const onReconnect = useCallback(
    (oldEdge: Edge, newConnection: Connection) => {
      setEdges((eds) =>
        reconnectEdge(oldEdge, newConnection, eds).map((edge) => {
          const edgeColor = getEdgeColor(edge.target, nodes)
          return {
            ...edge,
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: edgeColor,
            },
            style: {
              strokeWidth: 2,
              stroke: edgeColor,
            },
          }
        })
      )
      setHasUnsavedChanges(true)
    },
    [setEdges, nodes]
  )

  // Handle node selection
  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      setSelectedNode(node as FlowNode)
    },
    []
  )

  const onPaneClick = useCallback(() => {
    setSelectedNode(null)
  }, [])

  // Handle drag and drop from toolbox
  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }, [])

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault()

      if (!reactFlowWrapper.current || !reactFlowInstance) return

      const type = event.dataTransfer.getData('application/reactflow/type')
      const subtype = event.dataTransfer.getData('application/reactflow/subtype')

      if (!type) return

      const position = reactFlowInstance.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      })

      const newNode: FlowNode = {
        id: generateNodeId(type),
        type,
        position,
        data: {},
      }

      // Add type-specific data
      if (type === 'defense') {
        newNode.data.defense = subtype as DefenseType
      } else if (type === 'operator') {
        newNode.data.operator = subtype as OperatorType
        if (subtype === 'threshold_branch') {
          newNode.data.config = {
            ranges: [
              { min: 0, max: 30, output: 'low' },
              { min: 30, max: 60, output: 'medium' },
              { min: 60, max: 100, output: 'high' },
              { min: 100, max: null, output: 'critical' },
            ],
          }
        }
      } else if (type === 'action') {
        newNode.data.action = subtype as ActionType
        if (subtype === 'tarpit') {
          newNode.data.config = { delay_seconds: 10, then: 'block' }
        }
      } else if (type === 'observation') {
        newNode.data.observation = subtype as ObservationType
      }

      setNodes((nds) => nds.concat(newNode))
      setHasUnsavedChanges(true)
    },
    [reactFlowInstance, setNodes]
  )

  // Handle node updates from config panel
  const handleNodeUpdate = useCallback(
    (nodeId: string, updates: Partial<FlowNodeData>) => {
      setNodes((nds) =>
        nds.map((node) =>
          node.id === nodeId ? { ...node, data: { ...node.data, ...updates } as FlowNodeData } : node
        )
      )
      setSelectedNode((prev) =>
        prev?.id === nodeId ? { ...prev, data: { ...prev.data, ...updates } as FlowNodeData } : prev
      )
      setHasUnsavedChanges(true)
    },
    [setNodes]
  )

  // Handle node deletion
  const handleNodeDelete = useCallback(
    (nodeId: string) => {
      if (nodeId === 'start') {
        toast({
          title: 'Cannot Delete',
          description: 'The start node cannot be deleted.',
          variant: 'destructive',
        })
        return
      }
      setNodes((nds) => nds.filter((node) => node.id !== nodeId))
      setEdges((eds) => eds.filter((edge) => edge.source !== nodeId && edge.target !== nodeId))
      setSelectedNode(null)
      setHasUnsavedChanges(true)
    },
    [setNodes, setEdges, toast]
  )

  // Auto-layout handler (Top-to-Bottom)
  const handleAutoLayout = useCallback(() => {
    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(nodes, edges, 'TB')
    setNodes(layoutedNodes)
    setEdges(layoutedEdges)
    setHasUnsavedChanges(true)

    // Fit view after layout
    setTimeout(() => {
      reactFlowInstance?.fitView({ padding: 0.2 })
    }, 50)
  }, [nodes, edges, setNodes, setEdges, reactFlowInstance])

  // Save mutations
  const createMutation = useMutation({
    mutationFn: (data: Omit<DefenseProfile, 'builtin'>) => defenseProfilesApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defense-profiles'] })
      setHasUnsavedChanges(false)
      toast({
        title: 'Profile Created',
        description: 'Defense profile has been created successfully.',
      })
      navigate('/security/defense-profiles')
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<DefenseProfile> }) =>
      defenseProfilesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defense-profiles'] })
      queryClient.invalidateQueries({ queryKey: ['defense-profile', id] })
      setHasUnsavedChanges(false)
      toast({
        title: 'Profile Updated',
        description: 'Defense profile has been updated successfully.',
      })
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      })
    },
  })

  // Validate profile
  const validateMutation = useMutation({
    mutationFn: (profile: Omit<DefenseProfile, 'builtin'>) => defenseProfilesApi.validate(profile),
  })

  const handleSave = useCallback(async () => {
    // Validate form data
    if (!profileData.id || !profileData.name) {
      toast({
        title: 'Validation Error',
        description: 'Profile ID and Name are required.',
        variant: 'destructive',
      })
      return
    }

    // Build profile data
    const graphNodes = flowToGraph(nodes, edges)
    const profile: Omit<DefenseProfile, 'builtin'> = {
      id: profileData.id,
      name: profileData.name,
      description: profileData.description,
      enabled: true,
      priority: profileData.priority,
      graph: { nodes: graphNodes },
      settings: {
        default_action: 'allow',
        max_execution_time_ms: 100,
      },
      attack_signatures: attackSignatures,
    }

    // Validate graph structure
    const validation = await validateMutation.mutateAsync(profile)
    if (!validation.valid) {
      toast({
        title: 'Validation Error',
        description: validation.errors.join(', '),
        variant: 'destructive',
      })
      return
    }

    // Save
    if (isNew) {
      createMutation.mutate(profile)
    } else {
      updateMutation.mutate({ id: id!, data: profile })
    }
  }, [
    profileData,
    nodes,
    edges,
    isNew,
    id,
    createMutation,
    updateMutation,
    validateMutation,
    toast,
  ])

  // Navigation with unsaved changes warning
  const handleBack = useCallback(() => {
    if (hasUnsavedChanges) {
      setPendingNavigation('/security/defense-profiles')
      setShowUnsavedDialog(true)
    } else {
      navigate('/security/defense-profiles')
    }
  }, [hasUnsavedChanges, navigate])

  const confirmNavigation = useCallback(() => {
    setShowUnsavedDialog(false)
    if (pendingNavigation) {
      navigate(pendingNavigation)
    }
  }, [pendingNavigation, navigate])

  // Memoize node types to prevent re-renders
  const memoizedNodeTypes = useMemo(() => nodeTypes, [])

  // Extract defense types used by the current graph
  const profileDefenseTypes = useMemo(() => {
    const types = new Set<DefenseType>()
    for (const node of nodes) {
      if (node.type === 'defense' && node.data.defense) {
        types.add(node.data.defense as DefenseType)
      }
    }
    return Array.from(types)
  }, [nodes])

  // Handle attack signatures changes
  const handleAttackSignaturesChange = useCallback((newAttachment: AttackSignatureAttachment) => {
    setAttackSignatures(newAttachment)
    setHasUnsavedChanges(true)
  }, [])

  const isSaving = createMutation.isPending || updateMutation.isPending

  if (!isNew && isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b bg-background">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={handleBack}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h2 className="text-lg font-semibold">
              {isNew ? 'Create Defense Profile' : `Edit: ${profileData.name}`}
            </h2>
            {hasUnsavedChanges && (
              <span className="text-xs text-amber-500 flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                Unsaved changes
              </span>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          {!isNew && (
            <Button variant="outline" onClick={() => setShowSimulateDialog(true)}>
              <Play className="h-4 w-4 mr-2" />
              Simulate
            </Button>
          )}
          <Button onClick={handleSave} disabled={isSaving}>
            {isSaving ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Save className="h-4 w-4 mr-2" />
            )}
            {isNew ? 'Create Profile' : 'Save Changes'}
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'graph' | 'signatures')} className="flex-1 flex flex-col overflow-hidden">
        <div className="border-b px-4 bg-muted/30">
          <TabsList className="h-10">
            <TabsTrigger value="graph" className="flex items-center gap-2">
              <GitBranch className="h-4 w-4" />
              Defense Graph
            </TabsTrigger>
            <TabsTrigger value="signatures" className="flex items-center gap-2">
              <Target className="h-4 w-4" />
              Attack Signatures
              {attackSignatures?.items && attackSignatures.items.length > 0 && (
                <span className="ml-1 text-xs bg-primary/10 text-primary px-1.5 py-0.5 rounded-full">
                  {attackSignatures.items.length}
                </span>
              )}
            </TabsTrigger>
          </TabsList>
        </div>

        {/* Graph Tab */}
        <TabsContent value="graph" className="flex-1 overflow-hidden m-0 data-[state=inactive]:hidden">
          <div className="flex h-full overflow-hidden">
            {/* Left sidebar - Toolbox */}
            <NodeToolbox className="border-r h-full overflow-auto shrink-0" />

            {/* Center - React Flow canvas */}
            <div className="flex-1 relative" ref={reactFlowWrapper}>
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={handleNodesChange}
                onEdgesChange={handleEdgesChange}
                onConnect={onConnect}
                onReconnect={onReconnect}
                onNodeClick={onNodeClick}
                onPaneClick={onPaneClick}
                onDrop={onDrop}
                onDragOver={onDragOver}
                onInit={setReactFlowInstance}
                nodeTypes={memoizedNodeTypes}
                fitView
                snapToGrid
                snapGrid={[15, 15]}
                edgesReconnectable
                deleteKeyCode={['Backspace', 'Delete']}
                defaultEdgeOptions={{
                  type: 'smoothstep',
                  markerEnd: { type: MarkerType.ArrowClosed },
                }}
              >
                <Background variant={BackgroundVariant.Dots} gap={15} size={1} />
                <Controls />
                <MiniMap
                  nodeStrokeWidth={3}
                  zoomable
                  pannable
                  className="bg-background border rounded"
                />

                {/* Auto Layout button */}
                <Panel position="top-right" className="m-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleAutoLayout}
                    className="bg-background"
                  >
                    <LayoutGrid className="h-4 w-4 mr-2" />
                    Auto Layout
                  </Button>
                </Panel>

                {/* Profile metadata panel */}
                <Panel position="top-left" className="m-2">
                  <Card className="w-72">
                    <CardHeader className="py-2">
                      <CardTitle className="text-sm">Profile Settings</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 pb-3">
                      <div className="space-y-1">
                        <Label className="text-xs">ID</Label>
                        <Input
                          value={profileData.id}
                          onChange={(e) =>
                            setProfileData((d) => {
                              setHasUnsavedChanges(true)
                              return { ...d, id: e.target.value }
                            })
                          }
                          disabled={!isNew}
                          placeholder="my-profile"
                          className="text-sm h-8"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">Name</Label>
                        <Input
                          value={profileData.name}
                          onChange={(e) =>
                            setProfileData((d) => {
                              setHasUnsavedChanges(true)
                              return { ...d, name: e.target.value }
                            })
                          }
                          placeholder="My Profile"
                          className="text-sm h-8"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">Description</Label>
                        <Textarea
                          value={profileData.description}
                          onChange={(e) =>
                            setProfileData((d) => {
                              setHasUnsavedChanges(true)
                              return { ...d, description: e.target.value }
                            })
                          }
                          placeholder="Profile description..."
                          className="text-sm min-h-[60px]"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs">Priority</Label>
                        <Input
                          type="number"
                          value={profileData.priority}
                          onChange={(e) =>
                            setProfileData((d) => {
                              setHasUnsavedChanges(true)
                              return { ...d, priority: parseInt(e.target.value) || 500 }
                            })
                          }
                          className="text-sm h-8"
                        />
                      </div>
                    </CardContent>
                  </Card>
                </Panel>
              </ReactFlow>
            </div>

            {/* Right sidebar - Node config */}
            <NodeConfigPanel
              selectedNode={selectedNode}
              onNodeUpdate={handleNodeUpdate}
              onNodeDelete={handleNodeDelete}
              className="w-72 border-l h-full overflow-auto shrink-0"
            />
          </div>
        </TabsContent>

        {/* Signatures Tab */}
        <TabsContent value="signatures" className="flex-1 overflow-hidden m-0 data-[state=inactive]:hidden">
          <SignaturesTab
            attachment={attackSignatures}
            onAttachmentChange={handleAttackSignaturesChange}
            profileDefenseTypes={profileDefenseTypes}
            isBuiltin={profileResponse?.profile?.builtin}
          />
        </TabsContent>
      </Tabs>

      {/* Unsaved changes dialog */}
      <AlertDialog open={showUnsavedDialog} onOpenChange={setShowUnsavedDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved Changes</AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes. Are you sure you want to leave without saving?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmNavigation}>Leave Without Saving</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Simulate dialog */}
      {!isNew && id && (
        <SimulateDialog
          open={showSimulateDialog}
          onOpenChange={setShowSimulateDialog}
          profileId={id}
          profileName={profileData.name}
        />
      )}
    </div>
  )
}
