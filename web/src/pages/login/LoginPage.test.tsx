import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthContext } from '../../auth/AuthContext'
import { LoginPage } from './LoginPage'

afterEach(() => vi.restoreAllMocks())

describe('LoginPage', () => {
  it('posts credentials with the CSRF header and shows errors', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'invalid_credentials', message: 'x' } }), { status: 401 }),
    )
    render(
      <QueryClientProvider client={new QueryClient()}>
        <AuthContext.Provider value={{ me: null, setMe: () => {} }}>
          <MemoryRouter>
            <LoginPage />
          </MemoryRouter>
        </AuthContext.Provider>
      </QueryClientProvider>,
    )
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password.')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce())
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/auth/login')
    expect((init?.headers as Record<string, string>)['X-ASI-CSRF']).toBe('1')
    expect(JSON.parse(init?.body as string)).toEqual({ username: 'admin', password: 'pw' })
  })
})
