import type { HeaderProps } from "../types"

export default function PageHeader({ title, subtitle }: HeaderProps) {
  return (
    <section className="page-header">
      <h1>{title}</h1>
      <p>{subtitle}</p>
    </section>
  )
}