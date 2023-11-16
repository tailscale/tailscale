import cx from "classnames"
import React, { forwardRef, InputHTMLAttributes } from "react"
import { ReactComponent as Search } from "src/assets/icons/search.svg"

type Props = {
  className?: string
  inputClassName?: string
} & InputHTMLAttributes<HTMLInputElement>

/**
 * SearchInput is a standard input with a search icon.
 */
const SearchInput = forwardRef<HTMLInputElement, Props>((props, ref) => {
  const { className, inputClassName, ...rest } = props
  return (
    <div className={cx("relative", className)}>
      <Search className="absolute w-[1.25em] h-full ml-2" />
      <input
        type="text"
        className={cx("input px-8", inputClassName)}
        ref={ref}
        {...rest}
      />
    </div>
  )
})
SearchInput.displayName = "SearchInput"
export default SearchInput
