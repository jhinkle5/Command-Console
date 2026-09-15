import React, { useState } from 'react';
import { 
  Lock, 
  ShieldCheck, 
  Plus, 
  Trash2, 
  Power, 
  Sparkles, 
  Check, 
  Filter,
  AlertCircle
} from 'lucide-react';
import { FirewallRule } from '../types';
import { soundEffects } from '../utils/audio';

interface FirewallRuleManagerProps {
  rules: FirewallRule[];
  onAddRule: (rule: Omit<FirewallRule, 'id' | 'createdTime' | 'hitCount'>) => void;
  onToggleRule: (ruleId: string) => void;
  onDeleteRule: (ruleId: string) => void;
}

export const FirewallRuleManager: React.FC<FirewallRuleManagerProps> = ({
  rules,
  onAddRule,
  onToggleRule,
  onDeleteRule
}) => {
  const [showAddForm, setShowAddForm] = useState(false);
  const [name, setName] = useState('');
  const [action, setAction] = useState<'DROP' | 'REJECT' | 'ALLOW' | 'SINKHOLE'>('DROP');
  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [protocol, setProtocol] = useState('TCP');
  const [port, setPort] = useState('ANY');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !source) return;

    soundEffects.playQuarantineSuccess();
    onAddRule({
      name,
      action,
      source,
      destination: destination || '0.0.0.0/0',
      protocol,
      port: port || 'ANY',
      active: true,
      generatedBy: 'MANUAL'
    });

    setName('');
    setSource('');
    setDestination('');
    setPort('ANY');
    setShowAddForm(false);
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 text-xs font-mono">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800 mb-4">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          <h3 className="font-bold uppercase text-slate-200 tracking-wider">
            Stateful Border Firewall & Automated ACL Table
          </h3>
        </div>

        <button
          onClick={() => {
            soundEffects.playClick();
            setShowAddForm(!showAddForm);
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-950 border border-cyan-600/70 text-cyan-200 hover:bg-cyan-900 font-bold transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>{showAddForm ? 'CANCEL' : 'CREATE CUSTOM ACL RULE'}</span>
        </button>
      </div>

      {/* Add Rule Form */}
      {showAddForm && (
        <form onSubmit={handleSubmit} className="mb-4 p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
          <div className="font-bold text-slate-200 text-sm">DEFINE INLINE ACCESS CONTROL RULE</div>
          
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">RULE NAME</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Block Malicious Subnet"
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 block mb-1">ACTION</label>
              <select
                value={action}
                onChange={e => setAction(e.target.value as any)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="DROP">DROP (Silent Null-Route)</option>
                <option value="REJECT">REJECT (TCP RST)</option>
                <option value="SINKHOLE">SINKHOLE (Decoy Redirection)</option>
                <option value="ALLOW">ALLOW (Explicit Pass)</option>
              </select>
            </div>

            <div>
              <label className="text-[10px] text-slate-400 block mb-1">PROTOCOL</label>
              <select
                value={protocol}
                onChange={e => setProtocol(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
                <option value="ANY">ANY (All IP Protocols)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">SOURCE IP / CIDR</label>
              <input
                type="text"
                value={source}
                onChange={e => setSource(e.target.value)}
                placeholder="e.g. 198.51.100.0/24 or single IP"
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 block mb-1">DESTINATION IP / CIDR</label>
              <input
                type="text"
                value={destination}
                onChange={e => setDestination(e.target.value)}
                placeholder="e.g. 0.0.0.0/0 or 10.0.1.0/24"
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 block mb-1">DESTINATION PORT</label>
              <input
                type="text"
                value={port}
                onChange={e => setPort(e.target.value)}
                placeholder="e.g. 443, 22, or ANY"
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-3 py-1.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded bg-cyan-950 border border-cyan-500 text-cyan-200 font-bold hover:bg-cyan-900"
            >
              Inject Rule to Firewall
            </button>
          </div>
        </form>
      )}

      {/* Rules Table */}
      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-left border-collapse">
          <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">STATUS</th>
              <th className="py-2.5 px-3">ACTION</th>
              <th className="py-2.5 px-3">RULE NAME</th>
              <th className="py-2.5 px-3">SOURCE</th>
              <th className="py-2.5 px-3">DESTINATION</th>
              <th className="py-2.5 px-2">PROTO</th>
              <th className="py-2.5 px-2">PORT</th>
              <th className="py-2.5 px-3">HITS</th>
              <th className="py-2.5 px-3">ORIGIN</th>
              <th className="py-2.5 px-2 text-right">CONTROLS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-[11px]">
            {rules.map(rule => {
              return (
                <tr key={rule.id} className={`hover:bg-slate-800/30 ${!rule.active ? 'opacity-40' : ''}`}>
                  <td className="py-2 px-3">
                    <button
                      onClick={() => {
                        soundEffects.playClick();
                        onToggleRule(rule.id);
                      }}
                      className={`p-1 rounded ${rule.active ? 'text-emerald-400' : 'text-slate-600'}`}
                      title={rule.active ? 'Disable rule' : 'Enable rule'}
                    >
                      <Power className="w-3.5 h-3.5" />
                    </button>
                  </td>
                  <td className="py-2 px-3">
                    <span className={`px-1.5 py-0.5 rounded font-bold text-[10px] ${
                      rule.action === 'DROP'
                        ? 'bg-red-950 border border-red-800 text-red-300'
                        : rule.action === 'SINKHOLE'
                        ? 'bg-purple-950 border border-purple-800 text-purple-300'
                        : rule.action === 'REJECT'
                        ? 'bg-amber-950 border border-amber-800 text-amber-300'
                        : 'bg-emerald-950 border border-emerald-800 text-emerald-300'
                    }`}>
                      {rule.action}
                    </span>
                  </td>
                  <td className="py-2 px-3 font-semibold text-slate-100">{rule.name}</td>
                  <td className="py-2 px-3 text-cyan-300">{rule.source}</td>
                  <td className="py-2 px-3 text-slate-300">{rule.destination}</td>
                  <td className="py-2 px-2 text-slate-400">{rule.protocol}</td>
                  <td className="py-2 px-2 text-slate-400">{rule.port}</td>
                  <td className="py-2 px-3 font-bold text-slate-200">{rule.hitCount.toLocaleString()}</td>
                  <td className="py-2 px-3">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      {rule.generatedBy}
                    </span>
                  </td>
                  <td className="py-2 px-2 text-right">
                    <button
                      onClick={() => {
                        soundEffects.playClick();
                        onDeleteRule(rule.id);
                      }}
                      className="p-1 text-slate-500 hover:text-red-400"
                      title="Delete rule"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
