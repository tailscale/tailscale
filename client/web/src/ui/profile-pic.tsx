import cx from "classnames"
import React from "react"

export default function ProfilePic({
  url,
  size = "large",
  className,
}: {
  url?: string
  size?: "small" | "medium" | "large"
  className?: string
}) {
  return (
    <div
      className={cx(
        "relative flex-shrink-0 rounded-full overflow-hidden",
        {
          "w-5 h-5": size === "small",
          "w-[26px] h-[26px]": size === "medium",
          "w-8 h-8": size === "large",
        },
        className
      )}
    >
      {url ? (
        <div
          className="w-full h-full flex pointer-events-none rounded-full bg-gray-200"
          style={{
            backgroundImage: `url(${url})`,
            backgroundSize: "cover",
          }}
        />
      ) : (
        <div className="w-full h-full flex pointer-events-none rounded-full border border-gray-400 border-dashed" />
      )}
    </div>
  )
}
