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

import { Shield, Eye, EyeOff, Loader2, CheckCircle } from 'lucide-react';
import { vaultApi } from '@/lib/api';
import { toast } from 'sonner';

const registerSchema = z.object({
    vault_name: z.string()
        .min(1, 'Vault name is required')
        .max(50, 'Vault name must be less than 50 characters')
        .regex(/^[a-zA-Z0-9_-]+$/, 'Vault name can only contain letters, numbers, hyphens, and underscores'),
    master_password: z.string()
        .min(12, 'Master password must be at least 12 characters')
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
            'Password must contain uppercase, lowercase, number, and special character'),
    confirm_password: z.string(),
}).refine((data) => data.master_password === data.confirm_password, {
    message: "Passwords don't match",
    path: ["confirm_password"],
});

type RegisterForm = z.infer<typeof registerSchema>;

export default function RegisterPage() {
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');


    const router = useRouter();

    const form = useForm<RegisterForm>({
        resolver: zodResolver(registerSchema),
        defaultValues: {
            vault_name: '',
            master_password: '',
            confirm_password: '',
        },
    });

    const calculatePasswordStrength = (password: string) => {
        let strength = 0;
        if (password.length >= 8) strength += 20;
        if (password.length >= 12) strength += 20;
        if (/[a-z]/.test(password)) strength += 20;
        if (/[A-Z]/.test(password)) strength += 20;
        if (/\d/.test(password)) strength += 10;
        if (/[@$!%*?&]/.test(password)) strength += 10;
        return strength;
    };

    const getStrengthColor = (strength: number) => {
        if (strength < 40) return 'bg-destructive';
        if (strength < 70) return 'bg-yellow-500';
        return 'bg-green-500';
    };

    const getStrengthText = (strength: number) => {
        if (strength < 40) return 'Weak';
        if (strength < 70) return 'Fair';
        return 'Strong';
    };

    const onSubmit = async (data: RegisterForm) => {
        setIsLoading(true);
        setError('');

        try {
            const result = await vaultApi.createVault({
                vault_name: data.vault_name,
                master_password: data.master_password,
            });

            if (result.success) {
                toast.success('Vault created successfully!');
                router.push('/login');
            } else {
                setError(result.error || 'Failed to create vault');
            }
        } catch (error) {
            console.error('Registration error:', error);
            setError('Network error occurred');
        } finally {
            setIsLoading(false);
        }
    };

    const watchPassword = form.watch('master_password');
    const currentStrength = calculatePasswordStrength(watchPassword || '');

    return (
        <div className="min-h-screen bg-background flex items-center justify-center p-4">
            <Card className="w-full max-w-md">
                <CardHeader className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="bg-primary p-3 rounded-full">
                            <Shield className="h-8 w-8 text-primary-foreground" />
                        </div>
                    </div>
                    <CardTitle className="text-2xl">Create Your Vault</CardTitle>
                    <CardDescription>
                        Set up a new secure password vault
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="vault_name">Vault Name</Label>
                            <Input
                                id="vault_name"
                                type="text"
                                placeholder="Choose a unique vault name"
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
                                    placeholder="Create a strong master password"
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

                            {watchPassword && (
                                <div className="space-y-2">
                                    <div className="flex justify-between items-center">
                                        <span className="text-sm text-muted-foreground">Password Strength</span>
                                        <span className={`text-sm ${currentStrength >= 70 ? 'text-green-500' :
                                            currentStrength >= 40 ? 'text-yellow-500' : 'text-destructive'
                                            }`}>
                                            {getStrengthText(currentStrength)}
                                        </span>
                                    </div>
                                    <div className="w-full bg-muted rounded-full h-2">
                                        <div
                                            className={`h-2 rounded-full transition-all duration-300 ${getStrengthColor(currentStrength)}`}
                                            style={{ width: `${currentStrength}%` }}
                                        />
                                    </div>
                                </div>
                            )}

                            {form.formState.errors.master_password && (
                                <p className="text-sm text-destructive">
                                    {form.formState.errors.master_password.message}
                                </p>
                            )}
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="confirm_password">Confirm Master Password</Label>
                            <div className="relative">
                                <Input
                                    id="confirm_password"
                                    type={showConfirmPassword ? 'text' : 'password'}
                                    placeholder="Confirm your master password"
                                    className="pr-10"
                                    {...form.register('confirm_password')}
                                />
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                >
                                    {showConfirmPassword ? (
                                        <EyeOff className="h-4 w-4 text-muted-foreground" />
                                    ) : (
                                        <Eye className="h-4 w-4 text-muted-foreground" />
                                    )}
                                </Button>
                            </div>
                            {form.formState.errors.confirm_password && (
                                <p className="text-sm text-destructive">
                                    {form.formState.errors.confirm_password.message}
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

                        <div className="space-y-4">
                            <div className="bg-muted/50 p-4 rounded-lg">
                                <h4 className="text-sm font-semibold mb-2 flex items-center">
                                    <Shield className="h-4 w-4 mr-2" />
                                    Security Requirements:
                                </h4>
                                <ul className="text-sm text-muted-foreground space-y-1">
                                    <li className={`flex items-center ${watchPassword && watchPassword.length >= 12 ? 'text-green-500' : ''}`}>
                                        <CheckCircle className="h-3 w-3 mr-2" />
                                        At least 12 characters
                                    </li>
                                    <li className={`flex items-center ${watchPassword && /[A-Z]/.test(watchPassword) ? 'text-green-500' : ''}`}>
                                        <CheckCircle className="h-3 w-3 mr-2" />
                                        Uppercase letter
                                    </li>
                                    <li className={`flex items-center ${watchPassword && /[a-z]/.test(watchPassword) ? 'text-green-500' : ''}`}>
                                        <CheckCircle className="h-3 w-3 mr-2" />
                                        Lowercase letter
                                    </li>
                                    <li className={`flex items-center ${watchPassword && /\d/.test(watchPassword) ? 'text-green-500' : ''}`}>
                                        <CheckCircle className="h-3 w-3 mr-2" />
                                        Number
                                    </li>
                                    <li className={`flex items-center ${watchPassword && /[@$!%*?&]/.test(watchPassword) ? 'text-green-500' : ''}`}>
                                        <CheckCircle className="h-3 w-3 mr-2" />
                                        Special character
                                    </li>
                                </ul>
                            </div>

                            <Button
                                type="submit"
                                className="w-full"
                                disabled={isLoading || currentStrength < 70}
                            >
                                {isLoading ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Creating Vault...
                                    </>
                                ) : (
                                    'Create Vault'
                                )}
                            </Button>
                        </div>
                    </form>

                    <div className="mt-6 text-center">
                        <p className="text-muted-foreground text-sm">
                            Already have a vault?{' '}
                            <Button
                                variant="link"
                                className="p-0 h-auto"
                                onClick={() => router.push('/login')}
                            >
                                Sign in here
                            </Button>
                        </p>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
} 