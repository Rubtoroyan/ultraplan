import { createHash, timingSafeEqual } from 'crypto'
import type { NextRequest } from 'next/server'
import { supabase } from '@/lib/supabase'

export const runtime = 'nodejs'
// Never cache: every call must reach Postgres or the ping is meaningless.
export const dynamic = 'force-dynamic'

const NO_STORE = { 'Cache-Control': 'no-store, max-age=0' }

// Keeps the Supabase free-tier project from hitting the 7-day inactivity pause.
// Callers:
//   - Vercel Cron (vercel.json, daily) — sends `Authorization: Bearer ${CRON_SECRET}`
//     automatically when CRON_SECRET is set on the project.
//   - External monitors (e.g. cron-job.org) — `Authorization: Bearer ${KEEPALIVE_SECRET}`
//     or `?key=${KEEPALIVE_SECRET}`.
// The GitHub Actions workflow (.github/workflows/supabase-keepalive.yml) is an
// independent backup that hits the Supabase REST API directly.

// Hash both sides so timingSafeEqual gets equal-length buffers.
function safeEqual(a: string, b: string) {
  const ha = createHash('sha256').update(a).digest()
  const hb = createHash('sha256').update(b).digest()
  return timingSafeEqual(ha, hb)
}

function isAuthorized(request: NextRequest) {
  const keepaliveSecret = process.env.KEEPALIVE_SECRET
  const cronSecret = process.env.CRON_SECRET

  const auth = request.headers.get('authorization') ?? ''
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : null
  const key = request.nextUrl.searchParams.get('key')

  // Fail closed: an unset secret never matches anything.
  if (bearer) {
    if (keepaliveSecret && safeEqual(bearer, keepaliveSecret)) return true
    if (cronSecret && safeEqual(bearer, cronSecret)) return true
  }
  if (key && keepaliveSecret && safeEqual(key, keepaliveSecret)) return true
  return false
}

export async function GET(request: NextRequest) {
  if (!isAuthorized(request)) {
    return Response.json({ ok: false, error: 'Unauthorized' }, { status: 401, headers: NO_STORE })
  }

  const timestamp = new Date().toISOString()

  // Real round-trip through PostgREST: write the heartbeat and read the row back.
  const { data, error } = await supabase
    .from('keep_alive')
    .update({ last_ping: timestamp })
    .eq('id', 1)
    .select('id')
    .limit(1)

  if (error) {
    return Response.json({ ok: false, error: error.message }, { status: 500, headers: NO_STORE })
  }
  if (!data || data.length === 0) {
    return Response.json(
      { ok: false, error: 'keep_alive row id=1 not found' },
      { status: 500, headers: NO_STORE }
    )
  }

  return Response.json({ ok: true, timestamp }, { headers: NO_STORE })
}
