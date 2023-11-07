import cx from "classnames"
import React from "react"

export default function ProfilePic({
  url,
  size = "medium",
}: {
  url: string
  size?: "small" | "medium"
}) {
  return (
    <div
      className={cx("relative flex-shrink-0 rounded-full overflow-hidden", {
        "w-5 h-5": size === "small",
        "w-8 h-8": size === "medium",
      })}
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
