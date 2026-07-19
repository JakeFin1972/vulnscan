import { useState } from 'react'
import { ChevronDown, ChevronRight, Terminal, Search, Wrench, CheckCircle2, ShieldCheck } from 'lucide-react'

interface Phase {
  number: string
  title: string
  description: string
  output: string
}

interface Skill {
  id: string
  name: string
  command: string
  description: string
  tagline: string
  icon: React.ReactNode
  color: string
  phases: Phase[]
}

const SKILLS: Skill[] = [
  {
    id: 'vulnscan',
    name: 'vulnscan',
    command: '/vulnscan',
    description:
      'Forward-taint adversarial vulnerability scanner. Starts where an attacker starts — at entry points they can reach — and traces data forward to dangerous sinks. Every candidate is then adversarially falsified before it reaches you. Only findings that survive disproof are reported.',
    tagline: 'Start here — find real, provably reachable vulnerabilities',
    icon: <Search className="h-5 w-5" />,
    color: 'teal',
    phases: [
      {
        number: '01',
        title: 'Recon',
        description:
          'Map the attack surface. Rank entry points by attacker proximity: unauthenticated network input first, then authenticated-but-low-trust, file/upload parsers, inter-service data, and finally attacker-influenceable config.',
        output: 'Ranked list of sources and dangerous sinks',
      },
      {
        number: '02',
        title: 'Hunt',
        description:
          'Trace each ranked source forward through the call graph to a dangerous sink. Agents can fan out per-module or per-entry-point in parallel. Each candidate is an end-to-end tainted path.',
        output: 'Candidate findings — source→sink paths with taint argument',
      },
      {
        number: '03',
        title: 'Disprove',
        description:
          'Actively try to kill every candidate. Look for sanitization on the path, dead code, framework-level protections, or wrong trust assumptions. Every kill is logged with a specific reason. Survivors are the ones you couldn\'t kill.',
        output: 'Survivors only — kill log documents every rejected candidate',
      },
      {
        number: '04',
        title: 'Report',
        description:
          'For each survivor: the minimum a developer needs to confirm the bug on their own authorized system, a targeted fix proposal, and the security test that should now pass. Never a weaponized, portable exploit.',
        output: 'JSON findings (id, severity, CWE, source, sink, path, repro, fix)',
      },
    ],
  },
  {
    id: 'vulnscan-fix',
    name: 'vulnscan-fix',
    command: '/vulnscan-fix',
    description:
      'Test-driven remediation for a single verified finding. Takes one finding from the scanner\'s report, writes a failing security test that proves the bug, then implements the smallest fix that closes the taint path. A fix without a failing-then-passing test is not a fix — it\'s a hope.',
    tagline: 'Fix one finding at a time, proven by a security test',
    icon: <Wrench className="h-5 w-5" />,
    color: 'blue',
    phases: [
      {
        number: '01',
        title: 'Reproduce',
        description:
          'Re-derive the bug from scratch — read the full source→sink path, confirm taint reaches the sink with no neutralizer, identify the single best place to break the path. If it can\'t be re-confirmed, report it as not reproduced. No invented fix.',
        output: 'Confirmed taint path and chosen fix point',
      },
      {
        number: '02',
        title: 'RED',
        description:
          'Write a security test that asserts safe behavior — and therefore fails today because the vulnerability exists. The test must exercise the real path, fail for the right reason, and be confirmed to fail before proceeding.',
        output: 'Failing security test (the bug is now pinned)',
      },
      {
        number: '03',
        title: 'GREEN',
        description:
          'Implement the minimal fix. Re-run the security test — it must now pass. Run the surrounding suite — no regressions. If the same vulnerable pattern appears at sibling call sites, they\'re noted as follow-ups.',
        output: 'Passing security test, no regressions',
      },
      {
        number: '04',
        title: 'Review',
        description:
          'Produce the diff, a two-sentence rationale (what was open, what closes it), the new test, regression results, residual risk, and the owner for the change. Hand off to vulnscan-verify before merge.',
        output: 'Reviewable diff package ready for independent verification',
      },
    ],
  },
  {
    id: 'vulnscan-verify',
    name: 'vulnscan-verify',
    command: '/vulnscan-verify',
    description:
      'Independent, read-only verification that a proposed fix actually closes the vulnerability and that its security test genuinely proves it. Assumes the fix is wrong until shown otherwise. NEEDS-WORK is a normal, expected outcome — a verifier that always passes is worthless.',
    tagline: 'Independent check before merge — read-only, assumes wrong until proven right',
    icon: <ShieldCheck className="h-5 w-5" />,
    color: 'orange',
    phases: [
      {
        number: '01',
        title: 'Test integrity',
        description:
          'Does the security test actually prove anything? Does it exercise the real source→sink path or a mock? Revert check: if the fix were undone, would this test fail? A test that wouldn\'t catch the re-introduced bug is theater.',
        output: 'Test integrity: pass / fail with reason',
      },
      {
        number: '02',
        title: 'Fix completeness',
        description:
          'Does the fix close the path, or just the one input the test uses? Check for other parameters, other callers, other HTTP verbs reaching the same sink, sibling sites with the identical pattern, and blocklist evasion.',
        output: 'Completeness: pass / fail — open sibling paths if any',
      },
      {
        number: '03',
        title: 'Behavior preservation',
        description:
          'Run the suite. Do legitimate inputs still work? A fix that breaks the feature is NEEDS-WORK, not PASS.',
        output: 'Behavior: pass / fail — regressions if any',
      },
      {
        number: '04',
        title: 'No new risk',
        description:
          'Did the fix introduce a different vulnerability — a new sink, a new trust assumption, secrets in logs? Produce the final verdict with specific, actionable required changes if not PASS.',
        output: 'Verdict: PASS / NEEDS-WORK / FAIL',
      },
    ],
  },
]

const COLOR_MAP: Record<string, { accent: string; bg: string; border: string; badge: string; phase: string }> = {
  teal: {
    accent: 'text-teal-400',
    bg: 'bg-teal-500/10',
    border: 'border-teal-500/30',
    badge: 'bg-teal-500/20 text-teal-300 border-teal-500/30',
    phase: 'bg-teal-600',
  },
  blue: {
    accent: 'text-blue-400',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    badge: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    phase: 'bg-blue-600',
  },
  orange: {
    accent: 'text-orange-400',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    badge: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    phase: 'bg-orange-600',
  },
}

function PhaseRow({ phase, color, isLast }: { phase: Phase; color: string; isLast: boolean }) {
  const [open, setOpen] = useState(false)
  const c = COLOR_MAP[color]

  return (
    <div className="relative">
      {!isLast && (
        <div className={`absolute left-[19px] top-10 bottom-0 w-0.5 ${c.bg} border-l border-dashed ${c.border}`} />
      )}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 hover:bg-slate-800/40 transition-colors text-left"
      >
        <div className={`flex-shrink-0 w-9 h-9 rounded-full ${c.phase} flex items-center justify-center text-white text-xs font-mono font-bold z-10 relative`}>
          {phase.number}
        </div>
        <div className="flex-1 min-w-0 pt-1.5">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-200">{phase.title}</span>
            {open
              ? <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
              : <ChevronRight className="h-3.5 w-3.5 text-slate-500" />}
          </div>
          {!open && (
            <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">{phase.description}</p>
          )}
        </div>
        <span className={`flex-shrink-0 self-start mt-1.5 text-xs px-2 py-0.5 rounded border font-mono ${c.badge}`}>
          {open ? 'output' : ''}
        </span>
      </button>
      {open && (
        <div className="pl-16 pr-4 pb-4 space-y-2">
          <p className="text-xs text-slate-400 leading-relaxed">{phase.description}</p>
          <div className={`text-xs rounded px-3 py-2 ${c.bg} border ${c.border} font-mono ${c.accent}`}>
            → {phase.output}
          </div>
        </div>
      )}
    </div>
  )
}

function SkillCard({ skill, defaultOpen }: { skill: Skill; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false)
  const c = COLOR_MAP[skill.color]

  return (
    <div className={`bg-slate-900 border ${c.border} rounded-lg overflow-hidden`}>
      {/* Header */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-4 hover:bg-slate-800/30 transition-colors"
      >
        <span className={c.accent}>{skill.icon}</span>
        <div className="flex-1 text-left">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-semibold text-slate-100">{skill.name}</span>
            <span className={`text-xs px-2 py-0.5 rounded border ${c.badge}`}>{skill.command}</span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">{skill.tagline}</p>
        </div>
        {open
          ? <ChevronDown className="h-4 w-4 text-slate-500 flex-shrink-0" />
          : <ChevronRight className="h-4 w-4 text-slate-500 flex-shrink-0" />}
      </button>

      {open && (
        <>
          {/* Description */}
          <div className="px-4 pb-4 border-t border-slate-800 pt-3">
            <p className="text-xs text-slate-400 leading-relaxed">{skill.description}</p>
            <div className="mt-3 flex items-center gap-2 bg-slate-950 rounded px-3 py-2 border border-slate-700">
              <Terminal className="h-3.5 w-3.5 text-slate-500 flex-shrink-0" />
              <code className="text-xs font-mono text-teal-400">{skill.command}</code>
              <span className="text-xs text-slate-600">— invoke in Claude Code CLI</span>
            </div>
          </div>

          {/* Phases */}
          <div className="border-t border-slate-800">
            <div className="px-4 py-2 text-xs text-slate-500 uppercase tracking-wider font-medium">
              Phases
            </div>
            <div className="divide-y divide-slate-800/50">
              {skill.phases.map((phase, i) => (
                <PhaseRow
                  key={phase.number}
                  phase={phase}
                  color={skill.color}
                  isLast={i === skill.phases.length - 1}
                />
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default function Workflow() {
  return (
    <div className="p-6 max-w-3xl space-y-6">
      <div>
        <h1 className="text-sm font-semibold text-slate-100">Workflow</h1>
        <p className="text-xs text-slate-500 mt-1">
          The three-skill methodology — invoke from the Claude Code CLI.
        </p>
      </div>

      {/* Flow diagram */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-teal-500/10 border border-teal-500/30 rounded text-teal-400 font-mono">
            <Search className="h-3.5 w-3.5" />
            /vulnscan
          </div>
          <span className="text-slate-600">→ findings →</span>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-blue-500/10 border border-blue-500/30 rounded text-blue-400 font-mono">
            <Wrench className="h-3.5 w-3.5" />
            /vulnscan-fix
          </div>
          <span className="text-slate-600">→ diff →</span>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-orange-500/10 border border-orange-500/30 rounded text-orange-400 font-mono">
            <ShieldCheck className="h-3.5 w-3.5" />
            /vulnscan-verify
          </div>
          <span className="text-slate-600">→</span>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-300 font-mono">
            <CheckCircle2 className="h-3.5 w-3.5 text-teal-400" />
            merge
          </div>
        </div>
        <p className="text-xs text-slate-600 mt-3">
          Each skill is a Claude Code skill — invoke with the command in your terminal running{' '}
          <code className="font-mono text-slate-500">claude</code>. Fix one finding per run;
          batch fixes hide regressions.
        </p>
      </div>

      {/* Skill cards */}
      <div className="space-y-4">
        {SKILLS.map((skill, i) => (
          <SkillCard key={skill.id} skill={skill} defaultOpen={i === 0} />
        ))}
      </div>

      {/* Design principle */}
      <div className="border border-slate-800 rounded-lg p-4 space-y-2">
        <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Prime directive</div>
        <p className="text-xs text-slate-500 leading-relaxed">
          This is defensive tooling for authorized code review only. A finding you cannot defend
          against your own disproof is not a finding — it is noise. A fix without a failing-then-passing
          test is not a fix — it is a hope. Authorized use confirmed before every scan.
        </p>
      </div>
    </div>
  )
}
