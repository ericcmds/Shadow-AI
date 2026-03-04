import OpenAI from 'openai'

client.chat.completions.create({ model: 'gpt-4.1', messages: [{role:'system', content:'You are an AI'}] })
