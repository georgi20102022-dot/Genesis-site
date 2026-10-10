import { createHash, randomBytes, createCipheriv, createDecipheriv, scryptSync } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import path from 'node:path';

const port = Number(process.env.PORT ?? 3001);
const usersPath = path.resolve(process.cwd(), 'data', 'users.json');

const TOKEN_SECRET = process.env.TOKEN_SECRET ?? 'genesis-secret-key-change-in-production';
const TOKEN_ALGORITHM = 'aes-256-gcm';
const TOKEN_IV_LENGTH = 16;
const TOKEN_AUTH_TAG_LENGTH = 16;

type FeatureIcon = 'combat' | 'movement' | 'visuals' | 'configs';

type UserRecord = {
  id: string;
  uid: number;
  username: string;
  email: string;
  passwordHash: string;
  createdAt: string;
  subscriptionTill: string;
  hwidStatus: string;
  friends: number;
  friendsList: string[];
  friendRequests: string[];
  sentRequests: string[];
};

type SessionRecord = {
  token: string;
  userId: string;
  createdAt: string;
};

const sessions = new Map<string, SessionRecord>();

const payload = {
  stats: [
    { label: 'Style', value: 'Clean private' },
    { label: 'Modules', value: '70+' },
    { label: 'Configs', value: 'Quick swap' },
    { label: 'Feel', value: 'Fast + clean' },
  ],
  features: [
    {
      title: 'Combat',
      description: 'Hits feel sharp, aim looks clean, and fights stay smooth instead of goofy.',
      icon: 'combat' as FeatureIcon,
    },
    {
      title: 'Movement',
      description: 'Speed, strafe and movement stuff feels smooth, not chunky and not weird.',
      icon: 'movement' as FeatureIcon,
    },
    {
      title: 'Visuals',
      description: 'HUD and visuals stay clean so the screen does not look like a mess.',
      icon: 'visuals' as FeatureIcon,
    },
    {
      title: 'Configs',
      description: 'Swap setups fast and keep your own layouts without rebuilding from zero.',
      icon: 'configs' as FeatureIcon,
    },
  ],
  products: [
    {
      id: 'sub-30',
      name: 'Genesis Client',
      price: '200₽',
      duration: '/ 30 days',
      badge: 'Chosen by 5.000 customers',
      description: 'Starter access if you just want to get in and play.',
      category: 'subscription',
      features: ['25+ visual features', 'Fast-acting modules', '24/7 user support', 'Frequent client updates'],
    },
    {
      id: 'sub-90',
      name: 'Genesis Client',
      price: '400₽',
      duration: '/ 90 days',
      badge: 'Chosen by 5.000 customers',
      description: 'Best middle option if you play a lot and want the full feel.',
      category: 'subscription',
      features: ['25+ visual features', 'Fast-acting modules', '24/7 user support', 'Frequent client updates'],
    },
    {
      id: 'sub-999',
      name: 'Genesis Client',
      price: '650₽',
      duration: '/ Lifetime',
      badge: 'Chosen by 5.000 customers',
      description: 'The long option. Buy it once and stop thinking about it.',
      category: 'subscription',
      features: ['25+ visual features', 'Fast-acting modules', '24/7 user support', 'Frequent client updates'],
    },
    {
      id: 'hwid-reset',
      name: 'Reset HWID',
      price: '189₽',
      duration: '',
      badge: 'Addition',
      description: 'Use this if you need a fast hardware reset on your account.',
      category: 'addition',
      features: [],
    },
  ],
};

async function ensureUserStore() {
  await fs.mkdir(path.dirname(usersPath), { recursive: true });

  try {
    await fs.access(usersPath);
  } catch {
    await fs.writeFile(usersPath, '[]\n', 'utf8');
  }
}

async function readUsers(): Promise<UserRecord[]> {
  await ensureUserStore();
  const raw = await fs.readFile(usersPath, 'utf8');
  const parsed = JSON.parse(raw) as Array<Partial<UserRecord>>;

  return parsed.map((user, index) => {
    const createdAt = user.createdAt ?? new Date().toISOString();

    return {
      id: user.id ?? randomBytes(8).toString('hex'),
      uid: user.uid ?? index + 1,
      username: user.username ?? `user${index + 1}`,
      email: user.email ?? `user${index + 1}@local.dev`,
      passwordHash: user.passwordHash ?? '',
      createdAt,
      subscriptionTill: user.subscriptionTill ?? plusDays(new Date(createdAt), 30),
      hwidStatus: user.hwidStatus ?? 'Linked',
      friends: user.friends ?? 0,
      friendsList: user.friendsList ?? [],
      friendRequests: user.friendRequests ?? [],
      sentRequests: user.sentRequests ?? [],
    };
  });
}

async function writeUsers(users: UserRecord[]) {
  await ensureUserStore();
  await fs.writeFile(usersPath, `${JSON.stringify(users, null, 2)}\n`, 'utf8');
}

function hashPassword(password: string) {
  return createHash('sha256').update(password).digest('hex');
}

function encryptToken(payload: string): string {
  const iv = randomBytes(TOKEN_IV_LENGTH);
  const key = scryptSync(TOKEN_SECRET, 'salt', 32);
  const cipher = createCipheriv(TOKEN_ALGORITHM, key, iv);
  
  let encrypted = cipher.update(payload, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

function decryptToken(token: string): string | null {
  try {
    const parts = token.split(':');
    if (parts.length !== 3) {
      return null;
    }
    
    const [ivHex, authTagHex, encrypted] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = scryptSync(TOKEN_SECRET, 'salt', 32);
    
    const decipher = createDecipheriv(TOKEN_ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch {
    return null;
  }
}

function makeToken(userId: string): string {
  const payload = JSON.stringify({
    userId,
    timestamp: Date.now(),
    nonce: randomBytes(16).toString('hex'),
  });
  
  return encryptToken(payload);
}

function sendJson(response: ServerResponse, statusCode: number, data: unknown) {
  response.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(data));
}

async function readBody(request: IncomingMessage) {
  const chunks: Buffer[] = [];

  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? (JSON.parse(raw) as Record<string, string>) : {};
}

function getTokenFromRequest(request: IncomingMessage): { token: string; userId: string } | null {
  const authHeader = request.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.slice('Bearer '.length);
  const decrypted = decryptToken(token);
  
  if (!decrypted) {
    return null;
  }
  
  try {
    const payload = JSON.parse(decrypted);
    
    if (!payload.userId || !payload.timestamp || !payload.nonce) {
      return null;
    }
    
    const tokenAge = Date.now() - payload.timestamp;
    const maxAge = 7 * 24 * 60 * 60 * 1000;
    
    if (tokenAge > maxAge) {
      return null;
    }
    
    return { token, userId: payload.userId };
  } catch {
    return null;
  }
}

function plusDays(date: Date, days: number) {
  const copy = new Date(date);
  copy.setDate(copy.getDate() + days);
  return copy.toISOString();
}

function sanitizeUser(user: UserRecord) {
  return {
    id: user.id,
    uid: user.uid,
    username: user.username,
    email: user.email,
    createdAt: user.createdAt,
    subscriptionTill: user.subscriptionTill,
    hwidStatus: user.hwidStatus,
    friends: user.friendsList.length,
  };
}

const server = createServer(async (request, response) => {
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (request.method === 'OPTIONS') {
    response.writeHead(204);
    response.end();
    return;
  }

  if (request.method === 'GET' && request.url === '/api/health') {
    sendJson(response, 200, { ok: true, service: 'genesis-client-backend' });
    return;
  }

  if (request.method === 'GET' && request.url === '/api/site-data') {
    sendJson(response, 200, payload);
    return;
  }

  if (request.method === 'POST' && request.url === '/api/auth/register') {
    try {
      const body = await readBody(request);
      const username = body.username?.trim();
      const email = body.email?.trim().toLowerCase();
      const password = body.password ?? '';
      const repeatPassword = body.repeatPassword ?? '';

      if (!username || !email || !password || !repeatPassword) {
        sendJson(response, 400, { error: 'Fill every field.' });
        return;
      }

      if (password !== repeatPassword) {
        sendJson(response, 400, { error: 'Passwords do not match.' });
        return;
      }

      if (password.length < 6) {
        sendJson(response, 400, { error: 'Password is too short.' });
        return;
      }

      const users = await readUsers();
      const emailTaken = users.some((user) => user.email === email);
      const usernameTaken = users.some((user) => user.username.toLowerCase() === username.toLowerCase());

      if (emailTaken || usernameTaken) {
        sendJson(response, 409, { error: 'That email or username is already used.' });
        return;
      }

      const now = new Date();
      const nextUser: UserRecord = {
        id: randomBytes(8).toString('hex'),
        uid: users.length + 1,
        username,
        email,
        passwordHash: hashPassword(password),
        createdAt: now.toISOString(),
        subscriptionTill: plusDays(now, 30),
        hwidStatus: 'Linked',
        friends: 0,
        friendsList: [],
        friendRequests: [],
        sentRequests: [],
      };

      users.push(nextUser);
      await writeUsers(users);

      const token = makeToken(nextUser.id);
      sessions.set(token, {
        token,
        userId: nextUser.id,
        createdAt: now.toISOString(),
      });

      sendJson(response, 201, {
        token,
        user: sanitizeUser(nextUser),
      });
      return;
    } catch {
      sendJson(response, 400, { error: 'Bad request.' });
      return;
    }
  }

  if (request.method === 'POST' && request.url === '/api/auth/login') {
    try {
      const body = await readBody(request);
      const email = body.email?.trim().toLowerCase();
      const password = body.password ?? '';

      if (!email || !password) {
        sendJson(response, 400, { error: 'Enter email and password.' });
        return;
      }

      const users = await readUsers();
      const user = users.find((entry) => entry.email === email);

      if (!user || user.passwordHash !== hashPassword(password)) {
        sendJson(response, 401, { error: 'Wrong email or password.' });
        return;
      }

      const token = makeToken(user.id);
      sessions.set(token, {
        token,
        userId: user.id,
        createdAt: new Date().toISOString(),
      });

      sendJson(response, 200, {
        token,
        user: sanitizeUser(user),
      });
      return;
    } catch {
      sendJson(response, 400, { error: 'Bad request.' });
      return;
    }
  }

  if (request.method === 'GET' && request.url === '/api/auth/me') {
    const tokenData = getTokenFromRequest(request);
    if (!tokenData) {
      sendJson(response, 401, { error: 'Invalid or missing token.' });
      return;
    }

    const session = sessions.get(tokenData.token);
    if (!session || session.userId !== tokenData.userId) {
      sendJson(response, 401, { error: 'Session expired.' });
      return;
    }

    const users = await readUsers();
    const user = users.find((entry) => entry.id === tokenData.userId);

    if (!user) {
      sessions.delete(tokenData.token);
      sendJson(response, 401, { error: 'User not found.' });
      return;
    }

    sendJson(response, 200, { user: sanitizeUser(user) });
    return;
  }

  if (request.method === 'POST' && request.url === '/api/auth/logout') {
    const tokenData = getTokenFromRequest(request);
    if (tokenData) {
      sessions.delete(tokenData.token);
    }

    sendJson(response, 200, { ok: true });
    return;
  }

  // Friends endpoints
  if (request.method === 'GET' && request.url === '/api/friends') {
    const tokenData = getTokenFromRequest(request);
    if (!tokenData) {
      sendJson(response, 401, { error: 'Unauthorized' });
      return;
    }

    const users = await readUsers();
    const currentUser = users.find((u) => u.id === tokenData.userId);

    if (!currentUser) {
      sendJson(response, 404, { error: 'User not found' });
      return;
    }

    const friendsData = currentUser.friendsList.map((friendId) => {
      const friend = users.find((u) => u.id === friendId);
      if (!friend) return null;

      return {
        id: friend.id,
        username: friend.username,
        status: 'offline' as const,
        lastSeen: 'Recently',
      };
    }).filter(Boolean);

    sendJson(response, 200, { friends: friendsData });
    return;
  }

  if (request.method === 'GET' && request.url === '/api/friends/requests') {
    const tokenData = getTokenFromRequest(request);
    if (!tokenData) {
      sendJson(response, 401, { error: 'Unauthorized' });
      return;
    }

    const users = await readUsers();
    const currentUser = users.find((u) => u.id === tokenData.userId);

    if (!currentUser) {
      sendJson(response, 404, { error: 'User not found' });
      return;
    }

    const incomingRequests = currentUser.friendRequests.map((requesterId) => {
      const requester = users.find((u) => u.id === requesterId);
      if (!requester) return null;

      return {
        id: requester.id,
        username: requester.username,
        type: 'incoming' as const,
      };
    }).filter(Boolean);

    const outgoingRequests = currentUser.sentRequests.map((targetId) => {
      const target = users.find((u) => u.id === targetId);
      if (!target) return null;

      return {
        id: target.id,
        username: target.username,
        type: 'outgoing' as const,
      };
    }).filter(Boolean);

    sendJson(response, 200, { 
      incoming: incomingRequests,
      outgoing: outgoingRequests,
    });
    return;
  }

  if (request.method === 'POST' && request.url === '/api/friends/add') {
    const tokenData = getTokenFromRequest(request);
    if (!tokenData) {
      sendJson(response, 401, { error: 'Unauthorized' });
      return;
    }

    try {
      const body = await readBody(request);
      const targetUsername = body.username?.trim();

      if (!targetUsername) {
        sendJson(response, 400, { error: 'Username is required' });
        return;
      }

      const users = await readUsers();
      const currentUser = users.find((u) => u.id === tokenData.userId);
      const targetUser = users.find((u) => u.username.toLowerCase() === targetUsername.toLowerCase());

      if (!currentUser) {
        sendJson(response, 404, { error: 'User not found' });
        return;
      }

      if (!targetUser) {
        sendJson(response, 404, { error: 'Target user not found' });
        return;
      }

      if (targetUser.id === currentUser.id) {
        sendJson(response, 400, { error: 'Cannot add yourself' });
        return;
      }

      if (currentUser.friendsList.includes(targetUser.id)) {
        sendJson(response, 400, { error: 'Already friends' });
        return;
      }

      if (currentUser.sentRequests.includes(targetUser.id)) {
        sendJson(response, 400, { error: 'Request already sent' });
        return;
      }

      if (targetUser.friendRequests.includes(currentUser.id)) {
        targetUser.friendRequests = targetUser.friendRequests.filter((id) => id !== currentUser.id);
        currentUser.sentRequests = currentUser.sentRequests.filter((id) => id !== targetUser.id);
        
        currentUser.friendsList.push(targetUser.id);
        targetUser.friendsList.push(currentUser.id);

        await writeUsers(users);

        sendJson(response, 200, { message: 'Friend added' });
        return;
      }

      currentUser.sentRequests.push(targetUser.id);
      targetUser.friendRequests.push(currentUser.id);

      await writeUsers(users);

      sendJson(response, 200, { message: 'Friend request sent' });
      return;
    } catch {
      sendJson(response, 400, { error: 'Bad request' });
      return;
    }
  }

  if (request.method === 'POST' && request.url === '/api/friends/accept') {
    const tokenData = getTokenFromRequest(request);
    if (!tokenData) {
      sendJson(response, 401, { error: 'Unauthorized' });
      return;
    }

    try {
      const body = await readBody(request);
      const requesterId = body.requesterId?.trim();

      if (!requesterId) {
        sendJson(response, 400, { error: 'Requester ID is required' });
        return;
      }

      const users = await readUsers();
      const currentUser = users.find((u) => u.id === tokenData.userId);
      const requester = users.find((u) => u.id === requesterId);

      if (!currentUser || !requester) {
        sendJson(response, 404, { error: 'User not found' });
        return;
      }

      if (!currentUser.friendRequests.includes(requesterId)) {
        sendJson(response, 400, { error: 'No friend request from this user' });
        return;
      }

      currentUser.friendRequests = currentUser.friendRequests.filter((id) => id !== requesterId);
      requester.sentRequests = requester.sentRequests.filter((id) => id !== currentUser.id);

      currentUser.friendsList.push(requesterId);
      requester.friendsList.push(currentUser.id);

      await writeUsers(users);

      sendJson(response, 200, { message: 'Friend request accepted' });
      return;
    } catch {
      sendJson(response, 400, { error: 'Bad request' });
      return;
    }
  }

  if (request.method === 'POST' && request.url === '/api/friends/reject') {
    const tokenData = getTokenFromRequest(request);
    if (!tokenData) {
      sendJson(response, 401, { error: 'Unauthorized' });
      return;
    }

    try {
      const body = await readBody(request);
      const requesterId = body.requesterId?.trim();

      if (!requesterId) {
        sendJson(response, 400, { error: 'Requester ID is required' });
        return;
      }

      const users = await readUsers();
      const currentUser = users.find((u) => u.id === tokenData.userId);
      const requester = users.find((u) => u.id === requesterId);

      if (!currentUser || !requester) {
        sendJson(response, 404, { error: 'User not found' });
        return;
      }

      currentUser.friendRequests = currentUser.friendRequests.filter((id) => id !== requesterId);
      requester.sentRequests = requester.sentRequests.filter((id) => id !== currentUser.id);

      await writeUsers(users);

      sendJson(response, 200, { message: 'Friend request rejected' });
      return;
    } catch {
      sendJson(response, 400, { error: 'Bad request' });
      return;
    }
  }

  if (request.method === 'DELETE' && request.url?.startsWith('/api/friends/')) {
    const tokenData = getTokenFromRequest(request);
    if (!tokenData) {
      sendJson(response, 401, { error: 'Unauthorized' });
      return;
    }

    const friendId = request.url.split('/api/friends/')[1];

    if (!friendId) {
      sendJson(response, 400, { error: 'Friend ID is required' });
      return;
    }

    const users = await readUsers();
    const currentUser = users.find((u) => u.id === tokenData.userId);
    const friend = users.find((u) => u.id === friendId);

    if (!currentUser || !friend) {
      sendJson(response, 404, { error: 'User not found' });
      return;
    }

    if (!currentUser.friendsList.includes(friendId)) {
      sendJson(response, 400, { error: 'Not friends with this user' });
      return;
    }

    currentUser.friendsList = currentUser.friendsList.filter((id) => id !== friendId);
    friend.friendsList = friend.friendsList.filter((id) => id !== currentUser.id);

    await writeUsers(users);

    sendJson(response, 200, { message: 'Friend removed' });
    return;
  }

  sendJson(response, 404, { error: 'Not found' });
});

server.listen(port, () => {
  console.log(`Genesis backend listening on http://localhost:${port}`);
});
