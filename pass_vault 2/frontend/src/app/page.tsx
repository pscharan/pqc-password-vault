'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { authUtils } from '@/lib/api';
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Shield, Lock, Key } from 'lucide-react';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    if (authUtils.isAuthenticated()) {
      router.push('/dashboard');
    }
  }, [router]);

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <div className="flex justify-center mb-6">
            <div className="bg-primary/10 p-4 rounded-full">
              <Shield className="h-16 w-16 text-primary" />
            </div>
          </div>
          <h1 className="text-5xl font-bold mb-4">
            PQ Password Manager
          </h1>
          <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            A secure post-quantum cryptography enabled password manager.
            Protect your passwords with cutting-edge encryption technology.
          </p>
          <div className="flex gap-4 justify-center">
            <Button
              size="lg"
              onClick={() => router.push('/login')}
            >
              Sign In
            </Button>
            <Button
              size="lg"
              variant="outline"
              onClick={() => router.push('/register')}
            >
              Create Vault
            </Button>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
          <Card>
            <CardHeader>
              <Lock className="h-12 w-12 text-primary mb-4" />
              <CardTitle>Quantum-Safe Security</CardTitle>
              <CardDescription>
                Advanced post-quantum cryptography ensures your passwords remain secure even against future quantum computers.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Key className="h-12 w-12 text-primary mb-4" />
              <CardTitle>Zero-Knowledge Architecture</CardTitle>
              <CardDescription>
                Your master password never leaves your device. We can&apos;t access your data even if we wanted to.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Shield className="h-12 w-12 text-primary mb-4" />
              <CardTitle>Military-Grade Encryption</CardTitle>
              <CardDescription>
                AES-256 encryption with secure key derivation protects your sensitive information.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </div>
    </div>
  );
}
