import { Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import Accounts from './pages/Accounts'
import Endpoints from './pages/Endpoints'
import NewScan from './pages/NewScan'
import Findings from './pages/Findings'
import Matrix from './pages/Matrix'
import History from './pages/History'
import Reports from './pages/Reports'
import Settings from './pages/Settings'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/targets" element={<Targets />} />
        <Route path="/accounts" element={<Accounts />} />
        <Route path="/endpoints" element={<Endpoints />} />
        <Route path="/scan" element={<NewScan />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/matrix" element={<Matrix />} />
        <Route path="/history" element={<History />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
    </Routes>
  )
}
