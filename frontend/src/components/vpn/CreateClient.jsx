import { useState } from 'react';
import { Plus, User, Loader2 } from 'lucide-react';
import { API_BASE_URL } from '../../App';

const CreateClient = ({ onClientCreated }) => {
  const [clientName, setClientName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!clientName.trim()) return;

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const response = await fetch(`${API_BASE_URL}/clients/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': 'your-django-api-key-for-authentication'
        },
        body: JSON.stringify({ name: clientName.trim() })
      });

      if (response.ok) {
        setSuccess('Client created successfully!');
        setClientName('');
        onClientCreated?.();

        // Clear success message after 3 seconds
        setTimeout(() => setSuccess(''), 3000);
      } else {
        const errorData = await response.json().catch(() => ({}));
        setError(errorData.message || 'Failed to create client');
      }
    } catch (err) {
      setError('Network error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-sm border border-gray-200">
      <div className="px-4 py-3 border-b border-gray-200">
        <h3 className="text-sm font-semibold text-gray-900 flex items-center">
          <Plus className="w-4 h-4 mr-2 text-green-600" />
          Create New Client
        </h3>
      </div>

      <div className="p-4">
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label htmlFor="clientName" className="block text-xs font-medium text-gray-700 mb-1">
              Client Name
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                id="clientName"
                value={clientName}
                onChange={(e) => setClientName(e.target.value)}
                placeholder="Enter client name"
                className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-sm text-sm focus:outline-none focus:ring-1 focus:ring-green-500 focus:border-green-500"
                disabled={loading}
              />
            </div>
          </div>

          {error && (
            <div className="text-xs text-red-600 bg-red-50 p-2 rounded-sm">
              {error}
            </div>
          )}

          {success && (
            <div className="text-xs text-green-600 bg-green-50 p-2 rounded-sm">
              {success}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !clientName.trim()}
            className="w-full flex items-center justify-center px-4 py-2 bg-green-600 text-white text-sm font-medium rounded-sm hover:bg-green-700 focus:outline-none focus:ring-1 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Creating...
              </>
            ) : (
              <>
                <Plus className="w-4 h-4 mr-2" />
                Create Client
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default CreateClient;