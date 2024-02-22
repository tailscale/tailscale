// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, {
  forwardRef,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react"
import { createPortal } from "react-dom"
import X from "src/assets/icons/x.svg?react"
import { noop } from "src/utils/util"
import { create } from "zustand"
import { shallow } from "zustand/shallow"

// Set up root element on the document body for toasts to render into.
const root = document.createElement("div")
root.id = "toast-root"
root.classList.add("relative", "z-20")
document.body.append(root)

const toastSpacing = remToPixels(1)

export type Toaster = {
  clear: () => void
  dismiss: (key: string) => void
  show: (props: Toast) => string
}

type Toast = {
  key?: string // key is a unique string value that ensures only one toast with a given key is shown at a time.
  className?: string
  variant?: "danger" // styling for the toast, undefined is neutral, danger is for failed requests
  message: React.ReactNode
  timeout?: number
  added?: number // timestamp of when the toast was added
}

type ToastWithKey = Toast & { key: string }

type State = {
  toasts: ToastWithKey[]
  maxToasts: number
  clear: () => void
  dismiss: (key: string) => void
  show: (props: Toast) => string
}

const useToasterState = create<State>((set, get) => ({
  toasts: [],
  maxToasts: 5,
  clear: () => {
    set({ toasts: [] })
  },
  dismiss: (key: string) => {
    set((prev) => ({
      toasts: prev.toasts.filter((t) => t.key !== key),
    }))
  },
  show: (props: Toast) => {
    const { toasts: prevToasts, maxToasts } = get()

    const propsWithKey = {
      key: Date.now().toString(),
      ...props,
    }
    const prevIdx = prevToasts.findIndex((t) => t.key === propsWithKey.key)

    // If the toast already exists, update it. Otherwise, append it.
    const nextToasts =
      prevIdx !== -1
        ? [
            ...prevToasts.slice(0, prevIdx),
            propsWithKey,
            ...prevToasts.slice(prevIdx + 1),
          ]
        : [...prevToasts, propsWithKey]

    set({
      // Get the last `maxToasts` toasts of the set.
      toasts: nextToasts.slice(-maxToasts),
    })
    return propsWithKey.key
  },
}))

const clearSelector = (state: State) => state.clear

const toasterSelector = (state: State) => ({
  show: state.show,
  dismiss: state.dismiss,
  clear: state.clear,
})

/**
 * useRawToasterForHook is meant to supply the hook function for hooks/toaster.
 * Use hooks/toaster instead.
 */
export const useRawToasterForHook = () =>
  useToasterState(toasterSelector, shallow)

type ToastProviderProps = {
  children: React.ReactNode
  canEscapeKeyClear?: boolean
}

/**
 * ToastProvider is the top-level toaster component. It stores the toast state.
 */
export default function ToastProvider(props: ToastProviderProps) {
  const { children, canEscapeKeyClear = true } = props
  const clear = useToasterState(clearSelector)

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (!canEscapeKeyClear) {
        return
      }
      if (e.key === "Esc" || e.key === "Escape") {
        clear()
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => {
      window.removeEventListener("keydown", handleKeyDown)
    }
  }, [canEscapeKeyClear, clear])

  return (
    <>
      {children}
      <ToastContainer />
    </>
  )
}

const toastContainerSelector = (state: State) => ({
  toasts: state.toasts,
  dismiss: state.dismiss,
})

/**
 * ToastContainer manages the positioning and animation for all currently
 * displayed toasts. It should only be used by ToastProvider.
 */
function ToastContainer() {
  const { toasts, dismiss } = useToasterState(toastContainerSelector, shallow)

  const [prevToasts, setPrevToasts] = useState<ToastWithKey[]>(toasts)
  useEffect(() => setPrevToasts(toasts), [toasts])

  const [refMap] = useState(() => new Map<string, HTMLDivElement>())
  const getOffsetForToast = useCallback(
    (key: string) => {
      let offset = 0

      let arr = toasts
      let index = arr.findIndex((t) => t.key === key)
      if (index === -1) {
        arr = prevToasts
        index = arr.findIndex((t) => t.key === key)
      }

      if (index === -1) {
        return offset
      }

      for (let i = arr.length; i > index; i--) {
        if (!arr[i]) {
          continue
        }
        const ref = refMap.get(arr[i].key)
        if (!ref) {
          continue
        }
        offset -= ref.offsetHeight
        offset -= toastSpacing
      }
      return offset
    },
    [refMap, prevToasts, toasts]
  )

  const toastsWithStyles = useMemo(
    () =>
      toasts.map((toast) => ({
        toast: toast,
        style: {
          transform: `translateY(${getOffsetForToast(toast.key)}px) scale(1.0)`,
        },
      })),
    [getOffsetForToast, toasts]
  )

  if (!root) {
    throw new Error("Could not find toast root") // should never happen
  }

  return createPortal(
    <div className="fixed bottom-6 right-6 z-[99]">
      {toastsWithStyles.map(({ toast, style }) => (
        <ToastBlock
          key={toast.key}
          ref={(ref) => ref && refMap.set(toast.key, ref)}
          toast={toast}
          onDismiss={dismiss}
          style={style}
        />
      ))}
    </div>,
    root
  )
}

/**
 * ToastBlock is the display of an individual toast, and also manages timeout
 * settings for a particular toast.
 */
const ToastBlock = forwardRef<
  HTMLDivElement,
  {
    toast: ToastWithKey
    onDismiss?: (key: string) => void
    style?: React.CSSProperties
  }
>(({ toast, onDismiss = noop, style }, ref) => {
  const { message, key, timeout = 5000, variant } = toast

  const [focused, setFocused] = useState(false)
  const dismiss = useCallback(() => onDismiss(key), [onDismiss, key])
  const onFocus = useCallback(() => setFocused(true), [])
  const onBlur = useCallback(() => setFocused(false), [])

  useEffect(() => {
    if (timeout <= 0 || focused) {
      return
    }
    const timerId = setTimeout(() => dismiss(), timeout)
    return () => clearTimeout(timerId)
  }, [dismiss, timeout, focused])

  return (
    <div
      className={cx(
        "transition ease-in-out animate-scale-in",
        "bottom-0 right-0 z-[99] w-[85vw] origin-bottom",
        "sm:min-w-[400px] sm:max-w-[500px]",
        "absolute shadow-sm rounded-md text-md flex items-center justify-between",
        {
          "text-white bg-gray-700": variant === undefined,
          "text-white bg-orange-400": variant === "danger",
        }
      )}
      aria-live="polite"
      ref={ref}
      onBlur={onBlur}
      onFocus={onFocus}
      onMouseEnter={onFocus}
      onMouseLeave={onBlur}
      tabIndex={0}
      style={style}
    >
      <span className="pl-4 py-3 pr-2">{message}</span>
      <button
        className="cursor-pointer opacity-75 hover:opacity-50 transition-opacity py-3 px-3"
        onClick={dismiss}
      >
        <X className="w-[1em] h-[1em] stroke-current" />
      </button>
    </div>
  )
})

function remToPixels(rem: number) {
  return (
    rem * Number.parseFloat(getComputedStyle(document.documentElement).fontSize)
  )
}
