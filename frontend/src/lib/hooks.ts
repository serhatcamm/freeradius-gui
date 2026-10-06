import { useCallback, useEffect, useRef, useState } from 'react'

import { ApiError } from '../api'

/**
 * Load data from the API with consistent loading/error handling.
 *
 * `reload` is returned so pages can refresh after a mutation without
 * remounting.
 */
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: readonly unknown[] = [],
): {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => Promise<void>
  setData: (value: T) => void
} {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const mounted = useRef(true)
  const loaderRef = useRef(loader)
  loaderRef.current = loader

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const run = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await loaderRef.current()
      if (mounted.current) setData(result)
    } catch (caught) {
      if (!mounted.current) return
      if (caught instanceof ApiError) {
        setError(caught.message)
      } else {
        setError(caught instanceof Error ? caught.message : 'Unexpected error')
      }
    } finally {
      if (mounted.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    void run()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return { data, error, loading, reload: run, setData }
}

/** Run a mutation with pending/error state and a uniform result shape. */
export function useAction(): {
  run: <T>(action: () => Promise<T>) => Promise<T | null>
  pending: boolean
  error: string | null
  clearError: () => void
} {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = useCallback(async <T,>(action: () => Promise<T>): Promise<T | null> => {
    setPending(true)
    setError(null)
    try {
      return await action()
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : caught instanceof Error
            ? caught.message
            : 'Unexpected error',
      )
      return null
    } finally {
      setPending(false)
    }
  }, [])

  return { run, pending, error, clearError: () => setError(null) }
}