import { createBrowserRouter } from "react-router-dom";
import { Shell } from "./components/Shell";
import { Login } from "./pages/Login";
import { Feed } from "./pages/Feed";
import { Projects } from "./pages/Projects";
import { ProjectDetail } from "./pages/ProjectDetail";
import { RunLive } from "./pages/RunLive";
import { Report } from "./pages/Report";
import { Help } from "./pages/Help";
import { Health } from "./pages/Health";
import { LlmSetup } from "./pages/LlmSetup";
import { Users } from "./pages/Users";
import { NotFound } from "./pages/NotFound";

// Login + the full-screen live run view sit outside the Shell; everything else renders inside it.
export const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  { path: "/projects/:projectId/runs/:runId", element: <RunLive /> },
  {
    element: <Shell />,
    children: [
      { path: "/", element: <Feed /> },
      { path: "/projects", element: <Projects /> },
      { path: "/projects/:projectId", element: <ProjectDetail /> },
      { path: "/projects/:projectId/report", element: <Report /> },
      { path: "/help", element: <Help /> },
      { path: "/health", element: <Health /> },
      { path: "/admin/llm", element: <LlmSetup /> },
      { path: "/admin/users", element: <Users /> },
    ],
  },
  { path: "*", element: <NotFound /> },
]);
