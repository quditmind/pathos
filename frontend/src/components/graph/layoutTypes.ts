/** A box to place; `parent` puts it inside a container (trust boundary). */
export interface LayoutNode {
  id: string;
  width: number;
  height: number;
  parent?: string;
  /** Containers are sized by the layout around their children. */
  container?: boolean;
}
export interface LayoutEdge {
  id: string;
  source: string;
  target: string;
}
export interface Placed {
  x: number;
  y: number;
  width: number;
  height: number;
}
