import { Injectable } from "@nestjs/common";
import { GoogleGenAI, HarmCategory, HarmBlockThreshold } from "@google/genai";

@Injectable()
export class ChatbotService {
    private genAI: GoogleGenAI;

    constructor() {
        this.genAI = new GoogleGenAI({
        project: "project-gcp-tst",
        location: "global",
        vertexai: true,
        });
    }

    async getResponse(question: string): Promise<string> {
        const modelName = "gemini-2.5-pro-preview-06-05";

        const stream = await this.genAI.models.generateContentStream({
        model: modelName,
        contents: [
            {
            role: "user",
            parts: [{ text: question }],
            },
        ],
        config: {
            maxOutputTokens: 1024,
            temperature: 1,
            topP: 1,
            seed: 0,
            safetySettings: [
            {
                category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                threshold: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
            },
            {
                category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                threshold: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
            },
            {
                category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                threshold: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
            },
            {
                category: HarmCategory.HARM_CATEGORY_HARASSMENT,
                threshold: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
            },
            ],
        },
        });

        let finalText = "";
        for await (const chunk of stream) {
        if (chunk.text) {
            finalText += chunk.text;
        }
        }

        return finalText;
    }
}
