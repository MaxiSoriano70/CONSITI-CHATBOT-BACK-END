import { Injectable, OnModuleInit } from "@nestjs/common";
import { GoogleGenAI, HarmCategory, HarmBlockThreshold } from "@google/genai";
import * as path from "path";
import * as fs from "fs";

@Injectable()
export class ChatbotService implements OnModuleInit {
    private genAI: GoogleGenAI;

    onModuleInit() {
        const credentialsPath = path.join(
        process.cwd(),
        process.env.GOOGLE_CREDENTIALS_PATH || ""
        );

        console.log("Cargando credenciales desde:", credentialsPath);

        if (!fs.existsSync(credentialsPath)) {
        throw new Error(`No se encontró el archivo de credenciales en: ${credentialsPath}`);
        }

        process.env.GOOGLE_APPLICATION_CREDENTIALS = credentialsPath;

        this.genAI = new GoogleGenAI({
        project: "project-gcp-tst",
        location: "global",
        vertexai: true,
        });
    }

    async getResponse(question: string): Promise<string> {
        const modelName = "gemini-2.0-flash-001";

        const stream = await this.genAI.models.generateContentStream({
        model: modelName,
        contents: [
            {
            role: "user",
            parts: [{ text: question }],
            },
        ],
        config: {
            systemInstruction: 'Responde siempre actuando como un analista de sistemas.',
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
