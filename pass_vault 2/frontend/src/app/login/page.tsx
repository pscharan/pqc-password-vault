'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Eye, EyeOff, Loader2 } from 'lucide-react';
import { vaultApi } from '@/lib/api';
import { toast } from 'sonner';

const loginSchema = z.object({
    vault_name: z.string().min(1, 'Vault name is required'),
    master_password: z.string().min(8, 'Master password must be at least 8 characters'),
});

type LoginForm = z.infer<typeof loginSchema>;

export default function LoginPage() {
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const router = useRouter();

    const form = useForm<LoginForm>({
        resolver: zodResolver(loginSchema),
        defaultValues: {
            vault_name: '',
            master_password: '',
        },
    });

    const onSubmit = async (data: LoginForm) => {
        setIsLoading(true);
        setError('');

        try {
            const result = await vaultApi.authenticateVault(data);

            if (result.success) {
                toast.success('Login successful!');
                router.push('/dashboard');
            } else {
                setError(result.error || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            setError('Network error occurred');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-background flex items-center justify-center p-4">
            <Card className="w-full max-w-md">
                <CardHeader className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="bg-primary p-3 rounded-full">
                            <Shield className="h-8 w-8 text-primary-foreground" />
                        </div>
                    </div>
                    <CardTitle className="text-2xl">Access Your Vault</CardTitle>
                    <CardDescription>
                        Enter your vault credentials to access your passwords
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="vault_name">Vault Name</Label>
                            <Input
                                id="vault_name"
                                type="text"
                                placeholder="Enter your vault name"
                                {...form.register('vault_name')}
                            />
                            {form.formState.errors.vault_name && (
                                <p className="text-sm text-destructive">
                                    {form.formState.errors.vault_name.message}
                                </p>
                            )}
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="master_password">Master Password</Label>
                            <div className="relative">
                                <Input
                                    id="master_password"
                                    type={showPassword ? 'text' : 'password'}
                                    placeholder="Enter your master password"
                                    className="pr-10"
                                    {...form.register('master_password')}
                                />
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                    onClick={() => setShowPassword(!showPassword)}
                                >
                                    {showPassword ? (
                                        <EyeOff className="h-4 w-4 text-muted-foreground" />
                                    ) : (
                                        <Eye className="h-4 w-4 text-muted-foreground" />
                                    )}
                                </Button>
                            </div>
                            {form.formState.errors.master_password && (
                                <p className="text-sm text-destructive">
                                    {form.formState.errors.master_password.message}
                                </p>
                            )}
                        </div>

                        {error && (
                            <Alert variant="destructive">
                                <AlertDescription>
                                    {error}
                                </AlertDescription>
                            </Alert>
                        )}

                        <Button
                            type="submit"
                            className="w-full"
                            disabled={isLoading}
                        >
                            {isLoading ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Accessing Vault...
                                </>
                            ) : (
                                'Access Vault'
                            )}
                        </Button>
                    </form>

                    <div className="mt-6 text-center">
                        <p className="text-muted-foreground text-sm">
                            Don&apos;t have a vault?{' '}
                            <Button
                                variant="link"
                                className="p-0 h-auto"
                                onClick={() => router.push('/register')}
                            >
                                Create one here
                            </Button>
                        </p>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
} 