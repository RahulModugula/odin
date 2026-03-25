// TypeScript with heavy any type usage and XSS risk
async function fetchUserData(userId: any): Promise<any> {
  const response = await fetch(`/api/users/${userId}`);
  const data: any = await response.json();
  return data;
}

function renderProfile(user: any): void {
  // XSS vulnerability
  document.getElementById('profile')!.innerHTML = `
    <h1>${user.name}</h1>
    <p>${user.bio}</p>
  `;

  // Debug code left in
  console.log('Rendering profile:', user);
  console.debug('User data:', JSON.stringify(user));
}

// Using var instead of const/let
var currentUser: any = null;
var sessionToken: any = null;

export { fetchUserData, renderProfile };
