// functions/lib/validators.js
export function passwordPolicyError(p) {
  if (!p || p.length < 8) return 'Password must be at least 8 characters.';
  if (!/[A-Z]/.test(p))   return 'Include at least one uppercase letter (A–Z).';
  if (!/\d/.test(p))      return 'Include at least one number (0–9).';
  return '';
}

export function generatePolicyPassword(len = 12) {
  const lowers = 'abcdefghijklmnopqrstuvwxyz';
  const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const digits = '0123456789';
  const all = lowers + uppers + digits;

  // ensure at least one of each required class
  const picks = [
    uppers[Math.floor(Math.random() * uppers.length)],
    digits[Math.floor(Math.random() * digits.length)],
  ];
  while (picks.length < len) {
    picks.push(all[Math.floor(Math.random() * all.length)]);
  }
  // shuffle
  for (let i = picks.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [picks[i], picks[j]] = [picks[j], picks[i]];
  }
  return picks.join('');
}
