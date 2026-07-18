import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import Scans from './pages/Scans'
import Languages from './pages/Languages'
import Settings from './pages/Settings'
import DynamicScan from './pages/DynamicScan'
import EASM from './pages/EASM'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/dynamic" element={<DynamicScan />} />
        <Route path="/easm" element={<EASM />} />
        <Route path="/languages" element={<Languages />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}
