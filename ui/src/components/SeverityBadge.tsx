import type { Severity } from '@/types'
import { cn } from '@/lib/utils'

const MAP: Record<Severity, { label: string; cls: string }> = {
  critical: { label: 'CRITICAL', cls: 'bg-red-500/15 text-red-400 border-red-500/30' },
  high:     { label: 'HIGH',     cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
  medium:   { label: 'MEDIUM',   cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
  low:      { label: 'LOW',      cls: 'bg-blue-400/15 text-blue-400 border-blue-400/30' },
  info:     { label: 'INFO',     cls: 'bg-slate-700/50 text-slate-400 border-slate-600' },
}

interface Props {
  severity: Severity
  className?: string
}

export default function SeverityBadge({ severity, className }: Props) {
  const { label, cls } = MAP[severity] ?? MAP.info
  return (
    <span
      className={cn(
        'inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono font-medium border',
        cls,
        className,
      )}
    >
      {label}
    </span>
  )
}
