export function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem('token');
  
  if (!token) {
    console.warn('No auth token found in localStorage');
    return {};
  }
  
  return {
    'Authorization': `Bearer ${token}`
  };
}

export function getAuthHeadersWithJson(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    ...getAuthHeaders()
  };
}