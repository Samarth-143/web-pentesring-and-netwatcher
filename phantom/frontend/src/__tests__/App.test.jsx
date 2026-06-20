import React from 'react'
import { render } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import App from '../App.jsx'

describe('Phantom App Component', () => {
  it('renders without crashing', () => {
    // The App component renders a login screen initially when unauthenticated
    const { container } = render(<App />)
    expect(container).toBeTruthy()
    // Verify login screen elements are present
    expect(container.textContent).toContain('PHANTOM')
    expect(container.textContent).toContain('SecOps Audit')
  })
})
