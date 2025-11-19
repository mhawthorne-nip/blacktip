import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import { Devices } from '@/pages/Devices'
import { Timeline } from '@/pages/Timeline'
import { SpeedTest } from '@/pages/SpeedTest'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Devices />} />
          <Route path="timeline" element={<Timeline />} />
          <Route path="speedtest" element={<SpeedTest />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
