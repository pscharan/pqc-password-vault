'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import {
    Shield,
    Search,
    Copy,
    Eye,
    EyeOff,
    Trash2,
    LogOut,
    Globe,
    RefreshCw,
    Plus,
    Tag,
    User,
    Lock
} from 'lucide-react';
import { passwordApi, vaultApi, authUtils, PasswordEntry } from '@/lib/api';
import { toast } from 'sonner';

export default function DashboardPage() {
    const [passwords, setPasswords] = useState<PasswordEntry[]>([]);
    const [filteredPasswords, setFilteredPasswords] = useState<PasswordEntry[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [visiblePasswordIds, setVisiblePasswordIds] = useState<Set<number>>(new Set());
    const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const router = useRouter();

    // Form state for adding new password
    const [newPassword, setNewPassword] = useState({
        service_name: '',
        username: '',
        password: '',
        website_url: '',
        notes: '',
        tags: ''
    });

    useEffect(() => {
        if (!authUtils.isAuthenticated()) {
            router.push('/login');
            return;
        }
        loadPasswords();
    }, [router]);

    useEffect(() => {
        if (searchQuery.trim()) {
            const filtered = passwords.filter(
                (password) =>
                    password.service_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                    password.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
                    password.website_url?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                    password.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
            );
            setFilteredPasswords(filtered);
        } else {
            setFilteredPasswords(passwords);
        }
    }, [searchQuery, passwords]);

    const loadPasswords = async () => {
        try {
            setIsLoading(true);
            const result = await passwordApi.listPasswords();
            if (result.success) {
                setPasswords(result.services || []);
            } else {
                toast.error('Failed to load passwords');
            }
        } catch (error) {
            console.error('Failed to load passwords:', error);
            toast.error('Failed to load passwords');
        } finally {
            setIsLoading(false);
        }
    };

    const handleAddPassword = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newPassword.service_name.trim() || !newPassword.username.trim() || !newPassword.password.trim()) {
            toast.error('Please fill in all required fields');
            return;
        }

        try {
            setIsSubmitting(true);
            const result = await passwordApi.storePassword({
                service_name: newPassword.service_name.trim(),
                username: newPassword.username.trim(),
                password: newPassword.password,
                website_url: newPassword.website_url.trim() || undefined,
                notes: newPassword.notes.trim() || undefined,
                tags: newPassword.tags ? newPassword.tags.split(',').map(tag => tag.trim()).filter(Boolean) : []
            });

            if (result.success) {
                toast.success('Password added successfully');
                setIsAddDialogOpen(false);
                setNewPassword({
                    service_name: '',
                    username: '',
                    password: '',
                    website_url: '',
                    notes: '',
                    tags: ''
                });
                loadPasswords();
            } else {
                toast.error('Failed to add password');
            }
        } catch (error) {
            console.error('Failed to add password:', error);
            toast.error('Failed to add password');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleLogout = async () => {
        try {
            await vaultApi.logout();
            toast.success('Logged out successfully');
            router.push('/');
        } catch (error) {
            console.error('Error during logout:', error);
            toast.error('Error during logout');
        }
    };

    const handleViewPassword = async (serviceName: string, entryId: number) => {
        try {
            const result = await passwordApi.getPassword(serviceName);
            if (result.success && result.entry) {
                setVisiblePasswordIds(prev => new Set([...prev, entryId]));
                setPasswords(prev => prev.map(p =>
                    p.id === entryId ? { ...p, password: result.entry.password } : p
                ));
            } else {
                toast.error('Failed to retrieve password');
            }
        } catch (error) {
            console.error('Failed to retrieve password:', error);
            toast.error('Failed to retrieve password');
        }
    };

    const handleCopyPassword = async (serviceName: string) => {
        try {
            const result = await passwordApi.getPassword(serviceName);
            if (result.success && result.entry?.password) {
                await navigator.clipboard.writeText(result.entry.password);
                toast.success('Password copied to clipboard');
            } else {
                toast.error('Failed to copy password');
            }
        } catch (error) {
            console.error('Failed to copy password:', error);
            toast.error('Failed to copy password');
        }
    };

    const handleDeletePassword = async (entryId: number, serviceName: string) => {
        if (!confirm(`Are you sure you want to delete the password for ${serviceName}?`)) {
            return;
        }

        try {
            const result = await passwordApi.deletePassword(entryId);
            if (result.success) {
                toast.success('Password deleted successfully');
                loadPasswords();
            } else {
                toast.error('Failed to delete password');
            }
        } catch (error) {
            console.error('Failed to delete password:', error);
            toast.error('Failed to delete password');
        }
    };

    const getServiceIcon = (serviceName: string) => {
        return serviceName.charAt(0).toUpperCase();
    };

    return (
        <div className="min-h-screen bg-background">
            {/* Header */}
            <div className="border-b bg-card/50 backdrop-blur-sm">
                <div className="container mx-auto px-4 py-4 flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                        <div className="bg-primary p-2 rounded-lg">
                            <Shield className="h-6 w-6 text-primary-foreground" />
                        </div>
                        <div>
                            <h1 className="text-xl font-bold">PQ Password Vault</h1>
                            <p className="text-sm text-muted-foreground">Secure Password Manager</p>
                        </div>
                    </div>

                    <div className="flex items-center space-x-2">
                        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
                            <DialogTrigger asChild>
                                <Button>
                                    <Plus className="h-4 w-4 mr-2" />
                                    Add Password
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-[525px]">
                                <DialogHeader>
                                    <DialogTitle>Add New Password</DialogTitle>
                                    <DialogDescription>
                                        Store a new password securely in your vault.
                                    </DialogDescription>
                                </DialogHeader>
                                <form onSubmit={handleAddPassword} className="space-y-4">
                                    <div className="grid gap-4">
                                        <div className="grid gap-2">
                                            <Label htmlFor="service">Service Name *</Label>
                                            <div className="relative">
                                                <Shield className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                                <Input
                                                    id="service"
                                                    placeholder="e.g., Gmail, Facebook, etc."
                                                    value={newPassword.service_name}
                                                    onChange={(e) => setNewPassword(prev => ({ ...prev, service_name: e.target.value }))}
                                                    className="pl-10"
                                                    required
                                                />
                                            </div>
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="username">Username *</Label>
                                            <div className="relative">
                                                <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                                <Input
                                                    id="username"
                                                    placeholder="Username or email"
                                                    value={newPassword.username}
                                                    onChange={(e) => setNewPassword(prev => ({ ...prev, username: e.target.value }))}
                                                    className="pl-10"
                                                    required
                                                />
                                            </div>
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="password">Password *</Label>
                                            <div className="relative">
                                                <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                                <Input
                                                    id="password"
                                                    type="password"
                                                    placeholder="Enter password"
                                                    value={newPassword.password}
                                                    onChange={(e) => setNewPassword(prev => ({ ...prev, password: e.target.value }))}
                                                    className="pl-10"
                                                    required
                                                />
                                            </div>
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="website">Website URL</Label>
                                            <div className="relative">
                                                <Globe className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                                <Input
                                                    id="website"
                                                    placeholder="https://example.com"
                                                    value={newPassword.website_url}
                                                    onChange={(e) => setNewPassword(prev => ({ ...prev, website_url: e.target.value }))}
                                                    className="pl-10"
                                                />
                                            </div>
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="tags">Tags</Label>
                                            <div className="relative">
                                                <Tag className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                                                <Input
                                                    id="tags"
                                                    placeholder="work, personal, social (comma separated)"
                                                    value={newPassword.tags}
                                                    onChange={(e) => setNewPassword(prev => ({ ...prev, tags: e.target.value }))}
                                                    className="pl-10"
                                                />
                                            </div>
                                        </div>
                                        <div className="grid gap-2">
                                            <Label htmlFor="notes">Notes</Label>
                                            <Input
                                                id="notes"
                                                placeholder="Additional notes (optional)"
                                                value={newPassword.notes}
                                                onChange={(e) => setNewPassword(prev => ({ ...prev, notes: e.target.value }))}
                                            />
                                        </div>
                                    </div>
                                    <div className="flex justify-end space-x-2">
                                        <Button
                                            type="button"
                                            variant="outline"
                                            onClick={() => setIsAddDialogOpen(false)}
                                            disabled={isSubmitting}
                                        >
                                            Cancel
                                        </Button>
                                        <Button type="submit" disabled={isSubmitting}>
                                            {isSubmitting ? 'Adding...' : 'Add Password'}
                                        </Button>
                                    </div>
                                </form>
                            </DialogContent>
                        </Dialog>

                        <Button
                            variant="outline"
                            size="sm"
                            onClick={loadPasswords}
                        >
                            <RefreshCw className="h-4 w-4 mr-2" />
                            Refresh
                        </Button>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={handleLogout}
                        >
                            <LogOut className="h-4 w-4 mr-2" />
                            Logout
                        </Button>
                    </div>
                </div>
            </div>

            <div className="container mx-auto px-4 py-8">
                {/* Search */}
                <div className="flex flex-col sm:flex-row gap-4 mb-8">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input
                            placeholder="Search passwords..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="pl-10"
                        />
                    </div>
                </div>

                {/* Password Grid */}
                {isLoading ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {[...Array(6)].map((_, i) => (
                            <Card key={i} className="animate-pulse">
                                <CardHeader>
                                    <div className="h-4 bg-muted rounded w-3/4"></div>
                                    <div className="h-3 bg-muted rounded w-1/2"></div>
                                </CardHeader>
                                <CardContent>
                                    <div className="h-3 bg-muted rounded w-full mb-2"></div>
                                    <div className="h-3 bg-muted rounded w-2/3"></div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                ) : filteredPasswords.length === 0 ? (
                    <Card>
                        <CardContent className="text-center py-12">
                            <Shield className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
                            <h3 className="text-lg font-semibold mb-2">
                                {searchQuery ? 'No passwords found' : 'No passwords yet'}
                            </h3>
                            <p className="text-muted-foreground mb-4">
                                {searchQuery
                                    ? 'Try adjusting your search terms'
                                    : 'Get started by adding your first password'
                                }
                            </p>
                            {!searchQuery && (
                                <Button onClick={() => setIsAddDialogOpen(true)}>
                                    <Plus className="h-4 w-4 mr-2" />
                                    Add Your First Password
                                </Button>
                            )}
                        </CardContent>
                    </Card>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {filteredPasswords.map((password) => (
                            <Card key={password.id} className="hover:shadow-md transition-shadow">
                                <CardHeader className="pb-3">
                                    <div className="flex items-start justify-between">
                                        <div className="flex items-center space-x-3">
                                            <Avatar className="h-10 w-10">
                                                <AvatarFallback className="bg-primary text-primary-foreground">
                                                    {getServiceIcon(password.service_name)}
                                                </AvatarFallback>
                                            </Avatar>
                                            <div className="min-w-0 flex-1">
                                                <CardTitle className="text-base truncate">
                                                    {password.service_name}
                                                </CardTitle>
                                                <CardDescription className="truncate">
                                                    {password.username}
                                                </CardDescription>
                                            </div>
                                        </div>
                                    </div>
                                </CardHeader>

                                <CardContent className="pt-0">
                                    {password.website_url && (
                                        <div className="flex items-center text-sm text-muted-foreground mb-2">
                                            <Globe className="h-3 w-3 mr-1" />
                                            <span className="truncate">{password.website_url}</span>
                                        </div>
                                    )}

                                    {password.tags.length > 0 && (
                                        <div className="flex flex-wrap gap-1 mb-3">
                                            {password.tags.slice(0, 3).map((tag, index) => (
                                                <Badge key={index} variant="secondary" className="text-xs">
                                                    {tag}
                                                </Badge>
                                            ))}
                                            {password.tags.length > 3 && (
                                                <Badge variant="secondary" className="text-xs">
                                                    +{password.tags.length - 3}
                                                </Badge>
                                            )}
                                        </div>
                                    )}

                                    {/* Password field */}
                                    <div className="mb-4">
                                        <div className="flex items-center space-x-2">
                                            <div className="flex-1 bg-muted/50 rounded p-2 min-h-[36px] flex items-center">
                                                {visiblePasswordIds.has(password.id) && password.password ? (
                                                    <span className="font-mono text-sm break-all">
                                                        {password.password}
                                                    </span>
                                                ) : (
                                                    <span className="text-muted-foreground text-sm">••••••••••••</span>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Action buttons */}
                                    <div className="flex justify-between items-center">
                                        <div className="flex space-x-1">
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() => handleViewPassword(password.service_name, password.id)}
                                                className="h-8 w-8 p-0"
                                            >
                                                {visiblePasswordIds.has(password.id) ? (
                                                    <EyeOff className="h-4 w-4" />
                                                ) : (
                                                    <Eye className="h-4 w-4" />
                                                )}
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() => handleCopyPassword(password.service_name)}
                                                className="h-8 w-8 p-0"
                                            >
                                                <Copy className="h-4 w-4" />
                                            </Button>
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() => handleDeletePassword(password.id, password.service_name)}
                                                className="h-8 w-8 p-0 hover:text-destructive"
                                            >
                                                <Trash2 className="h-4 w-4" />
                                            </Button>
                                        </div>
                                        <span className="text-xs text-muted-foreground">
                                            {new Date(password.created_at).toLocaleDateString()}
                                        </span>
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
} 