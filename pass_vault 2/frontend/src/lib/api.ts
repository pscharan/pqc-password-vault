import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

// Create axios instance
const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Request interceptor to add auth token
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('auth_token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Response interceptor to handle auth errors
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('auth_token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

// API Types
export interface VaultCreateRequest {
    vault_name: string;
    master_password: string;
}

export interface VaultAuthRequest {
    vault_name: string;
    master_password: string;
}

export interface PasswordEntry {
    id: number;
    service_name: string;
    username: string;
    password?: string;
    notes?: string;
    website_url?: string;
    tags: string[];
    created_at: string;
    updated_at: string;
}

export interface PasswordStoreRequest {
    service_name: string;
    username: string;
    password: string;
    notes?: string;
    website_url?: string;
    tags?: string[];
}

export interface PasswordGenerateRequest {
    length: number;
    include_uppercase: boolean;
    include_lowercase: boolean;
    include_numbers: boolean;
    include_symbols: boolean;
    exclude_ambiguous: boolean;
}

// API Functions
export const vaultApi = {
    createVault: async (data: VaultCreateRequest) => {
        const response = await api.post('/vault/create', data);
        return response.data;
    },

    authenticateVault: async (data: VaultAuthRequest) => {
        const response = await api.post('/vault/auth', data);
        if (response.data.success && response.data.session_token) {
            localStorage.setItem('auth_token', response.data.session_token);
        }
        return response.data;
    },

    logout: async () => {
        try {
            await api.post('/vault/logout');
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            localStorage.removeItem('auth_token');
        }
    }
};

export const passwordApi = {
    listPasswords: async () => {
        const response = await api.get('/passwords');
        return response.data;
    },

    getPassword: async (serviceName: string) => {
        const response = await api.get(`/passwords/${encodeURIComponent(serviceName)}`);
        return response.data;
    },

    storePassword: async (data: PasswordStoreRequest) => {
        const response = await api.post('/passwords', data);
        return response.data;
    },

    updatePassword: async (entryId: number, data: Partial<PasswordStoreRequest>) => {
        const response = await api.put(`/passwords/${entryId}`, data);
        return response.data;
    },

    deletePassword: async (entryId: number) => {
        const response = await api.delete(`/passwords/${entryId}`);
        return response.data;
    },

    searchPasswords: async (query: string) => {
        const response = await api.post('/passwords/search', { query });
        return response.data;
    },

    generatePassword: async (options: PasswordGenerateRequest) => {
        const response = await api.post('/passwords/generate', options);
        return response.data;
    },

    validatePassword: async (password: string) => {
        const response = await api.post('/passwords/validate', { password });
        return response.data;
    }
};

export const healthApi = {
    check: async () => {
        const response = await api.get('/health');
        return response.data;
    }
};

// Auth utility functions
export const authUtils = {
    isAuthenticated: () => {
        return !!localStorage.getItem('auth_token');
    },

    getToken: () => {
        return localStorage.getItem('auth_token');
    },

    logout: () => {
        localStorage.removeItem('auth_token');
    }
}; 