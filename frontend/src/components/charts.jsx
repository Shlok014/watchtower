import { Line, Doughnut, Bar } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, Tooltip, Legend, Filler,
} from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Tooltip, Legend, Filler)

/* Empty states say which of the two things is true — no data yet, or nothing to
   show — rather than the single "Collecting data…" that used to appear whether
   the backend was busy, empty, or unreachable. */
export function TimelineChart({ data, empty }) {
  if (!data || !data.length) return <div className="empty-state">{empty || 'No data yet'}</div>
  const chartData = {
    labels: data.map(d => d.time),
    datasets: [
      {
        label: 'Logs', data: data.map(d => d.logs), fill: true,
        borderColor: '#38bdf8', backgroundColor: 'rgba(56,189,248,0.06)',
        pointRadius: 1.5, pointHoverRadius: 5, tension: 0.4, borderWidth: 2,
      },
      {
        label: 'Alerts', data: data.map(d => d.alerts), fill: true,
        borderColor: '#f87171', backgroundColor: 'rgba(248,113,113,0.08)',
        pointRadius: 1.5, pointHoverRadius: 5, tension: 0.4, borderWidth: 2,
      },
    ],
  }
  const opts = {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: {
      legend: { position: 'top', labels: { color: '#94a3b8', font: { size: 11, weight: '600' }, padding: 16, usePointStyle: true, pointStyle: 'dash', pointStyleWidth: 20 } },
      tooltip: { backgroundColor: '#0c1220', borderColor: '#38bdf8', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' },
    },
    scales: {
      x: { ticks: { color: '#475569', font: { size: 8, family: "'JetBrains Mono'" }, maxRotation: 45 }, grid: { color: 'rgba(56,189,248,0.04)' } },
      y: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: 'rgba(56,189,248,0.06)' }, beginAtZero: true },
    },
  }
  return <Line data={chartData} options={opts} />
}

export function AlertDistChart({ data }) {
  const total = data ? (data.critical || 0) + (data.high || 0) + (data.medium || 0) + (data.low || 0) : 0
  if (!total) return <div className="empty-state">No alerts raised yet</div>
  const chartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [data.critical || 0, data.high || 0, data.medium || 0, data.low || 0],
      backgroundColor: ['rgba(239,68,68,0.8)', 'rgba(248,113,113,0.7)', 'rgba(251,191,36,0.7)', 'rgba(52,211,153,0.7)'],
      borderColor: ['#ef4444', '#f87171', '#fbbf24', '#34d399'],
      borderWidth: 2, hoverOffset: 8,
    }],
  }
  const opts = {
    responsive: true, maintainAspectRatio: false, animation: false,
    plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 10 }, padding: 14, usePointStyle: true, pointStyleWidth: 8 } } },
    cutout: '65%',
  }
  return <Doughnut data={chartData} options={opts} />
}

export function EventDistChart({ data }) {
  if (!data || Object.keys(data).length === 0) return <div className="empty-state">No events ingested yet</div>
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8)
  const chartData = {
    labels: sorted.map(([k]) => k.replace(/_/g, ' ')),
    datasets: [{
      data: sorted.map(([, v]) => v),
      backgroundColor: [
        'rgba(56,189,248,0.6)', 'rgba(248,113,113,0.6)', 'rgba(251,191,36,0.6)',
        'rgba(52,211,153,0.6)', 'rgba(167,139,250,0.6)', 'rgba(244,114,182,0.6)',
        'rgba(96,165,250,0.6)', 'rgba(74,222,128,0.6)',
      ],
      borderRadius: 4, borderSkipped: false,
    }],
  }
  const opts = {
    responsive: true, maintainAspectRatio: false, indexAxis: 'y', animation: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: 'rgba(56,189,248,0.06)' } },
      y: { ticks: { color: '#94a3b8', font: { size: 9, family: "'JetBrains Mono'" } }, grid: { display: false } },
    },
  }
  return <Bar data={chartData} options={opts} />
}
