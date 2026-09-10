import { createBrowserRouter } from "react-router-dom";
import { Login } from "./pages/Login";
import { Health } from "./pages/Health";
import { Projects } from "./pages/Projects";
import { ProjectDetail } from "./pages/ProjectDetail";
import { RunLive } from "./pages/RunLive";
import { Report } from "./pages/Report";
import { Approvals } from "./pages/Approvals";
import { NotFound } from "./pages/NotFound";

// Route inventory (pages fill in Phase 2): login, projects, project dashboard, scope, run/live,
// findings, catalog, report, approvals, admin/users, audit.
export const router = createBrowserRouter([
  { path: "/", element: <Projects /> },
  { path: "/login", element: <Login /> },
  { path: "/health", element: <Health /> },
  { path: "/projects", element: <Projects /> },
  { path: "/projects/:projectId", element: <ProjectDetail /> },
  { path: "/projects/:projectId/runs/:runId", element: <RunLive /> },
  { path: "/projects/:projectId/report", element: <Report /> },
  { path: "/projects/:projectId/approvals", element: <Approvals /> },
  { path: "*", element: <NotFound /> },
]);
