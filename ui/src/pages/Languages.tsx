import { useState, useEffect, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CheckCircle2, XCircle, Plus, X, Loader2, ChevronRight,
  AlertCircle, Save,
} from 'lucide-react'
import { listLanguages, getLanguage, createLanguage, updateLanguage } from '@/api'
import type { LanguageDetail } from '@/types'

// CodeMirror
import { EditorView, basicSetup } from 'codemirror'
import { yaml as yamlLang } from '@codemirror/lang-yaml'
import { oneDark } from '@codemirror/theme-one-dark'
import { useRef } from 'react'

const EXAMPLE_YAML = `name: mylang
extensions: [".ml"]
grammar: tree_sitter_mylang
sources:
  - id: http_entry
    category: http_handler
    match:
      node: function_definition
      has_attribute: [Route]
sinks:
  - id: sql_exec
    category: sql_query
    match:
      node: call_expression
      callee_leaf_in: [execute, query]
`

function CodeEditor({
  value,
  onChange,
}: {
  value: string
  onChange: (v: string) => void
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)

  useEffect(() => {
    if (!containerRef.current) return
    const view = new EditorView({
      doc: value,
      extensions: [
        basicSetup,
        yamlLang(),
        oneDark,
        EditorView.theme({
          '&': { height: '100%', fontSize: '12px', fontFamily: 'JetBrains Mono, monospace' },
          '.cm-scroller': { overflow: 'auto' },
          '&.cm-focused': { outline: 'none' },
        }),
        EditorView.updateListener.of((update: import('@codemirror/view').ViewUpdate) => {
          if (update.docChanged) onChange(update.state.doc.toString())
        }),
      ],
      parent: containerRef.current,
    })
    viewRef.current = view
    return () => view.destroy()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Sync external value changes
  useEffect(() => {
    const view = viewRef.current
    if (!view) return
    const current = view.state.doc.toString()
    if (current !== value) {
      view.dispatch({ changes: { from: 0, to: current.length, insert: value } })
    }
  }, [value])

  return <div ref={containerRef} className="h-full overflow-hidden rounded border border-slate-700" />
}

interface ValidationState {
  checking: boolean
  ok?: boolean
  error?: string
  sourceCount?: number
  sinkCount?: number
}

export default function Languages() {
  const qc = useQueryClient()
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editingName, setEditingName] = useState<string | null>(null)
  const [yamlContent, setYamlContent] = useState(EXAMPLE_YAML)
  const [validation, setValidation] = useState<ValidationState>({ checking: false })
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const langsQ = useQuery({ queryKey: ['languages'], queryFn: listLanguages })
  const languages = langsQ.data ?? []

  // Load existing def for editing
  const editQ = useQuery({
    queryKey: ['language', editingName],
    queryFn: () => getLanguage(editingName!),
    enabled: !!editingName,
  })

  useEffect(() => {
    if (editingName && editQ.data) {
      setYamlContent(editQ.data.yaml_content)
      setValidation({ checking: false })
    }
  }, [editingName, editQ.data])

  const openAdd = useCallback(() => {
    setEditingName(null)
    setYamlContent(EXAMPLE_YAML)
    setValidation({ checking: false })
    setSaveError(null)
    setDrawerOpen(true)
  }, [])

  const openEdit = useCallback((name: string) => {
    setEditingName(name)
    setValidation({ checking: false })
    setSaveError(null)
    setDrawerOpen(true)
  }, [])

  const closeDrawer = useCallback(() => {
    setDrawerOpen(false)
    setEditingName(null)
    setSaveError(null)
  }, [])

  // Live validation with debounce
  const validateTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const handleYamlChange = useCallback((content: string) => {
    setYamlContent(content)
    setValidation({ checking: true })
    if (validateTimer.current) clearTimeout(validateTimer.current)
    validateTimer.current = setTimeout(async () => {
      try {
        // Parse YAML client-side first for quick feedback
        const yamlMod = await import('yaml')
        const parse = yamlMod.parse
        // Try counting rules
        try {
          const parsed = parse(content) as LanguageDetail
          const sourceCount = (parsed?.sources as unknown[])?.length ?? 0
          const sinkCount = (parsed?.sinks as unknown[])?.length ?? 0
          setValidation({ checking: false, ok: true, sourceCount, sinkCount })
        } catch {
          setValidation({ checking: false, ok: false, error: 'Invalid YAML structure' })
        }
      } catch {
        setValidation({ checking: false, ok: false, error: 'Parse error' })
      }
    }, 500)
  }, [])

  async function handleSave() {
    setSaving(true)
    setSaveError(null)
    try {
      if (editingName) {
        await updateLanguage(editingName, yamlContent)
      } else {
        // Extract name from YAML for create
        const lines = yamlContent.split('\n')
        const nameLine = lines.find(l => l.startsWith('name:'))
        const name = nameLine?.replace('name:', '').trim() ?? 'unnamed'
        await createLanguage(name, yamlContent)
      }
      await qc.invalidateQueries({ queryKey: ['languages'] })
      closeDrawer()
    } catch (e: unknown) {
      setSaveError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex h-full">
      {/* Language list */}
      <div className="flex-1 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-sm font-semibold text-slate-100">Languages</h1>
          <button
            onClick={openAdd}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium rounded transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Language
          </button>
        </div>

        {langsQ.isLoading ? (
          <div className="flex items-center gap-2 text-slate-600 py-8">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-sm">Loading…</span>
          </div>
        ) : languages.length === 0 ? (
          <div className="text-sm text-slate-600 py-8 text-center">
            No language definitions found.
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {languages.map(lang => (
              <div
                key={lang.name}
                className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-100 text-sm">{lang.name}</span>
                      {lang.available ? (
                        <span title="Grammar installed"><CheckCircle2 className="h-3.5 w-3.5 text-teal-400" /></span>
                      ) : (
                        <span title="Grammar not installed"><XCircle className="h-3.5 w-3.5 text-slate-600" /></span>
                      )}
                    </div>
                    <div className="flex gap-1.5 mt-1 flex-wrap">
                      {lang.extensions.map(ext => (
                        <span key={ext} className="font-mono text-xs text-teal-400 bg-teal-500/10 px-1.5 py-0.5 rounded border border-teal-500/20">
                          {ext}
                        </span>
                      ))}
                    </div>
                  </div>
                  <button
                    onClick={() => openEdit(lang.name)}
                    className="text-slate-500 hover:text-slate-300 transition-colors p-1 -mr-1 -mt-1"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-slate-800/60 rounded p-2">
                    <div className="text-slate-500 text-xs">Sources</div>
                    <div className="text-slate-200 font-semibold">{lang.source_count}</div>
                  </div>
                  <div className="bg-slate-800/60 rounded p-2">
                    <div className="text-slate-500 text-xs">Sinks</div>
                    <div className="text-slate-200 font-semibold">{lang.sink_count}</div>
                  </div>
                </div>

                <div className="text-xs text-slate-600 font-mono">{lang.grammar}</div>

                {!lang.available && (
                  <div className="flex items-start gap-1.5 text-xs text-slate-500 bg-slate-800/40 rounded p-2">
                    <AlertCircle className="h-3 w-3 flex-shrink-0 mt-0.5 text-slate-600" />
                    Grammar not installed. Run:{' '}
                    <code className="text-yellow-500">pip install {lang.grammar.replace(/_/g, '-')}</code>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Editor drawer */}
      {drawerOpen && (
        <div className="w-[640px] flex-shrink-0 border-l border-slate-800 bg-slate-900 flex flex-col h-full">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <span className="text-sm font-medium text-slate-200">
              {editingName ? `Edit: ${editingName}` : 'Add Language'}
            </span>
            <button onClick={closeDrawer} className="text-slate-500 hover:text-slate-300 transition-colors">
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* 3-panel layout */}
          <div className="flex-1 flex flex-col min-h-0 p-4 gap-3">
            {/* Editor */}
            <div className="flex-1 min-h-0">
              <CodeEditor value={yamlContent} onChange={handleYamlChange} />
            </div>

            {/* Validation result */}
            <div className="bg-slate-950 border border-slate-700 rounded p-3 text-xs">
              <div className="text-slate-500 mb-1.5 uppercase tracking-wider text-xs">Validation</div>
              {validation.checking ? (
                <div className="flex items-center gap-1.5 text-slate-500">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Checking…
                </div>
              ) : validation.ok === true ? (
                <div className="flex items-center gap-1.5 text-teal-400">
                  <CheckCircle2 className="h-3 w-3" />
                  Valid YAML — {validation.sourceCount ?? 0} sources, {validation.sinkCount ?? 0} sinks
                </div>
              ) : validation.ok === false ? (
                <div className="flex items-start gap-1.5 text-red-400">
                  <XCircle className="h-3 w-3 flex-shrink-0 mt-0.5" />
                  <span>{validation.error ?? 'Invalid definition'}</span>
                </div>
              ) : (
                <div className="text-slate-600">Edit the YAML above to validate</div>
              )}
            </div>

            {/* Rule count preview */}
            <div className="bg-slate-950 border border-slate-700 rounded p-3 text-xs">
              <div className="text-slate-500 mb-1.5 uppercase tracking-wider text-xs">Preview</div>
              <div className="text-slate-400">
                {validation.ok === true
                  ? `${(validation.sourceCount ?? 0) + (validation.sinkCount ?? 0)} rules total`
                  : '—'}
              </div>
            </div>

            {/* Save */}
            {saveError && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2 font-mono">
                {saveError}
              </div>
            )}
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center justify-center gap-2 py-2 bg-teal-600 hover:bg-teal-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded transition-colors"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              {saving ? 'Saving…' : editingName ? 'Save Changes' : 'Create Language'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
