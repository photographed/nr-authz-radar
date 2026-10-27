export const dynamic = 'force-dynamic'
export default function Home () {
  return (
    <main style={{ fontFamily: 'sans-serif', padding: 24, lineHeight: 1.6 }}>
      <h1>nr-authz-radar — Next.js vulnerable demo</h1>
      <p>Local test fixture only. Never deploy. Run <code>./check.sh</code> and read the server log.</p>
      <ul>
        <li><code>GET /api/orders/[id]</code> — instrumented IDOR (D01 in observe mode)</li>
        <li><code>GET /api/raw/orders/[id]</code> — same IDOR, not instrumented (invisible)</li>
      </ul>
    </main>
  )
}
