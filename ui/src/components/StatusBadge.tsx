import type { ScanStatus } from '@/types'
import { cn } from '@/lib/utils'
import { Loader2 } from 'lucide-react'

const MAP: Record<ScanStatus, { label: string; cls: string; spin?: boolean }> = {
  pending: { label: 'Pending', cls: 'bg-slate-700/50 text-slate-400 border-slate-600' },
  running: { label: 'Running', cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30', spin: true },
  done:    { label: 'Done',    cls: 'bg-teal-500/15 text-teal-400 border-teal-500/30' },
  error:   { label: 'Error',   cls: 'bg-red-500/15 text-red-400 border-red-500/30' },
}

interface Props {
  status: ScanStatus
  className?: string
}

export default function StatusBadge({ status, className }: Props) {
  const { label, cls, spin } = MAP[status] ?? MAP.pending
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium border',
        cls,
        className,
      )}
    >
      {spin && <Loader2 className="h-3 w-3 animate-spin" />}
      {label}
    </span>
  )
}
