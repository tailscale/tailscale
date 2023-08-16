import React from "react"
import { Footer, Header, IP, State } from "src/components/legacy"
import useNodeData from "src/hooks/node-data"

export default function App() {
  // TODO(sonia): use isPosting value from useNodeData
  // to fill loading states.
  const { data, updateNode } = useNodeData()

  return (
    <div className="py-14">
      {!data ? (
        // TODO(sonia): add a loading view
        <div className="text-center">Loading...</div>
      ) : (
        <>
          <main className="container max-w-lg mx-auto mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
            <Header data={data} />
            <IP data={data} />
            <State data={data} updateNode={updateNode} />
          </main>
          <Footer data={data} />
        </>
      )}
    </div>
  )
}
