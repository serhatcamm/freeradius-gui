import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import App from './App'
import { AuthProvider } from './auth/AuthContext'
import './index.css'

const container = document.getElementById('root')
if (!container) {
  throw new Error('root element missing from index.html')
}

createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      {/* App reads the session through useAuth(), so the provider must wrap it.
          Without this the hook throws during render and the page stays blank. */}
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
)