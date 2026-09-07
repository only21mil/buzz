import type { ReactNode } from "react";
import { AppProfilePanelProvider } from "@/app/AppProfilePanelProvider";
import { AppWorkflowEditorOverlayProvider } from "@/app/AppWorkflowEditorOverlayProvider";

export function AppShellPanelProviders({ children }: { children: ReactNode }) {
  return (
    <AppProfilePanelProvider>
      <AppWorkflowEditorOverlayProvider>
        {children}
      </AppWorkflowEditorOverlayProvider>
    </AppProfilePanelProvider>
  );
}
