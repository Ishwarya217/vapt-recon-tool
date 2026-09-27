/// <reference types="vite/client" />

declare module 'lucide-react' {
  import React from 'react';
  export type Icon = React.FC<React.SVGProps<SVGSVGElement> & { size?: number | string }>;
  export const Activity: Icon;
  export const AlertTriangle: Icon;
  export const CheckCircle: Icon;
  export const CheckCircle2: Icon;
  export const ChevronRight: Icon;
  export const Clock: Icon;
  export const Cpu: Icon;
  export const Download: Icon;
  export const FileText: Icon;
  export const Globe: Icon;
  export const HardDrive: Icon;
  export const Info: Icon;
  export const LayoutDashboard: Icon;
  export const Lock: Icon;
  export const Play: Icon;
  export const Plus: Icon;
  export const RefreshCw: Icon;
  export const Search: Icon;
  export const Server: Icon;
  export const Settings: Icon;
  export const Shield: Icon;
  export const Terminal: Icon;
  export const Trash2: Icon;
  export const TrendingUp: Icon;
  export const XCircle: Icon;
  export const Zap: Icon;
  const anyIcon: Icon;
  export default anyIcon;
}
