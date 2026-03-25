// Good TypeScript with proper types
interface User {
  id: number;
  name: string;
  email: string;
  createdAt: Date;
}

interface ApiResponse<T> {
  data: T;
  error: string | null;
  status: number;
}

async function fetchUser(userId: number): Promise<ApiResponse<User>> {
  const response = await fetch(`/api/users/${userId}`);
  if (!response.ok) {
    return { data: null as unknown as User, error: `HTTP ${response.status}`, status: response.status };
  }
  const data = await response.json() as User;
  return { data, error: null, status: 200 };
}

function formatUserDisplay(user: User): string {
  const joined = new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'long' })
    .format(user.createdAt);
  return `${user.name} (joined ${joined})`;
}

export { fetchUser, formatUserDisplay };
export type { User, ApiResponse };
