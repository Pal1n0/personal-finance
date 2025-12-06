import { useEffect, useState } from 'react';
import useUserStore from '../store/useUserStore';
import apiClient from '../services/apiClient';
import { useQuery } from '@tanstack/react-query';
import type { User } from '../types';

export const useAuth = () => {
  const { token, isAuthenticated, user, setCredentials, logout } = useUserStore();
  const [loading, setLoading] = useState(true);

  const { data: userData, isFetching, isError } = useQuery<User>({
    queryKey: ['currentUser'],
    queryFn: async () => {
      const response = await apiClient.get('/api/auth/user/');
      return response.data;
    },
    enabled: isAuthenticated && !user, // Only fetch if authenticated and user data is missing
    staleTime: Infinity, // User data is considered always fresh once fetched
    cacheTime: 1000 * 60 * 60 * 24, // Cache for 24 hours
    retry: 3, // Retry failed requests 3 times
  });

  useEffect(() => {
    if (isAuthenticated && userData && !user) {
      // If we fetched user data and it's not yet in the store, set it.
      // We also need a dummy token here as setCredentials expects it.
      // The actual token is already in localStorage and the store.
      setCredentials(userData, token || ''); 
    }
    if (isAuthenticated && !isFetching) {
      setLoading(false);
    } else if (!isAuthenticated) {
      setLoading(false);
    }
  }, [isAuthenticated, userData, user, token, setCredentials, isFetching]);

  useEffect(() => {
    if (isError) {
      // If fetching user data failed (e.g., token expired or invalid)
      logout();
      setLoading(false);
    }
  }, [isError, logout]);

  return { isAuthenticated, user, loading };
};
