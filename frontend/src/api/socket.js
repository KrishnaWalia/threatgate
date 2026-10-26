import { io } from 'socket.io-client';
import { API_BASE_URL } from './http';

let socket = null;

/**
 * Opens (or reuses) a single Socket.io connection authenticated
 * with the same JWT the REST API uses. The token travels in the
 * connection handshake (`auth: { token }`), not as a query string,
 * so it never ends up logged in a URL anywhere.
 */
export function getSocket() {
  const token = localStorage.getItem('threatgate_token');
  if (!token) return null;

  if (socket && socket.active) return socket; // connected OR still connecting

  socket = io(API_BASE_URL, {
    auth: { token },
    transports: ['websocket'],
  });

  return socket;
}

export function disconnectSocket() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
}
