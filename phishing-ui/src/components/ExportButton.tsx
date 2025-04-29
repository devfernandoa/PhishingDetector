import React from 'react';

export const ExportButton: React.FC<{ data: any[] }> = ({ data }) => {
    const handleExport = () => {
        const rows: string[] = [];

        // Header
        const headers = ['domain', 'riskScore', 'issueType', 'message', 'timestamp'];
        rows.push(headers.join(','));

        // Flatten issues per result
        data.forEach(entry => {
            if (Array.isArray(entry.issues)) {
                entry.issues.forEach((issue: any) => {
                    const row = [
                        `"${entry.domain}"`,
                        entry.riskScore,
                        `"${issue.type}"`,
                        `"${issue.message.replace(/"/g, '""')}"`,
                        `"${new Date(entry.timestamp).toISOString()}"`
                    ];
                    rows.push(row.join(','));
                });
            } else {
                const row = [
                    `"${entry.domain}"`,
                    entry.riskScore,
                    `""`,
                    `"No issues reported"`,
                    `"${new Date(entry.timestamp).toISOString()}"`
                ];
                rows.push(row.join(','));
            }
        });

        const csv = rows.join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'scan-results.csv';
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <button
            onClick={handleExport}
            className="text-sm text-blue-600 hover:underline"
        >
            Export CSV
        </button>
    );
};
