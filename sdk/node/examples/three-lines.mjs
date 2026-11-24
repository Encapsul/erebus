import { attest } from 'erebus-sdk';
const answer = attest((question) => ({ answer: question.toUpperCase() }), { name: 'answer' });
answer('hello');
