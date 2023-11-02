import React from "react"

export default function ProfilePic({ url }: { url: string }) {
  return (
    <div className="relative flex-shrink-0 w-8 h-8 rounded-full overflow-hidden">
      {url ? (
        <div
          className="w-8 h-8 flex pointer-events-none rounded-full bg-gray-200"
          style={{
            backgroundImage: `url(${url})`,
            backgroundSize: "cover",
          }}
        />
      ) : (
        <div className="w-8 h-8 flex pointer-events-none rounded-full border border-gray-400 border-dashed" />
      )}
    </div>
  )
}
