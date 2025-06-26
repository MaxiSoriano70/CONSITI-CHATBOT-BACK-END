import { Injectable, OnModuleInit } from "@nestjs/common";
import { GoogleGenAI, HarmCategory, HarmBlockThreshold } from "@google/genai";
import * as path from "path";
import * as fs from "fs";

type ChatMessage = {
    role: "user" | "model";
    parts: { text: string }[];
};

@Injectable()
export class ChatbotService implements OnModuleInit {
    private genAI: GoogleGenAI;

    private sessionHistory: Record<string, ChatMessage[]> = {};

    onModuleInit() {
        const credentialsPath = path.join(
            process.cwd(),
            process.env.GOOGLE_CREDENTIALS_PATH || ""
        );

        console.log("Cargando credenciales desde:", credentialsPath);

        if (!fs.existsSync(credentialsPath)) {
            throw new Error(
                `No se encontró el archivo de credenciales en: ${credentialsPath}`
            );
        }

        process.env.GOOGLE_APPLICATION_CREDENTIALS = credentialsPath;

        this.genAI = new GoogleGenAI({
            project: "project-gcp-tst",
            location: "global",
            vertexai: true,
        });
    }

    private getSystemInstruction(): string {
        return `
            Actúa como un analista de sistemas senior, especializado en el levantamiento de requerimientos y diseño técnico de sistemas. Tu objetivo es asistir en la planificación de soluciones tecnológicas adecuadas a partir de las necesidades del cliente.

            Sigue estas directrices estrictamente:

            1. **Analiza el contexto**: presupuesto disponible, tipo de usuarios, dispositivos que usarán, conectividad, conocimientos técnicos del cliente, y facilidad de mantenimiento.
            2. **Recomienda el tipo de sistema más adecuado**: aplicación web, móvil o escritorio, justificando tu elección.
            3. **Sugiere tecnologías y lenguajes de programación adecuados** según el tipo de sistema y el presupuesto (económico o con alta inversión).
            4. **Propón una metodología de desarrollo** como SCRUM, Kanban, cascada, etc., basada en el tamaño del equipo y el tipo de proyecto.
            5. **Genera al menos 3 historias de usuario**, utilizando el siguiente formato:

                - Como [rol del usuario], quiero [acción o funcionalidad], para [objetivo o beneficio].

            6. **Crea el código PlantUML de un diagrama de casos de uso** basado en las historias de usuario generadas. Usa el siguiente estilo:

            \`\`\`plantuml
            @startuml
            :Usuario: --> (Acción)
            @enduml
            \`\`\`

            ### Estructura esperada de la respuesta:
            - Evaluación del contexto
            - Tipo de sistema recomendado
            - Tecnologías sugeridas
            - Metodología de desarrollo
            - Historias de usuario clave
            - Diagrama de casos de uso (en PlantUML)

            🛑 Si la solicitud no contiene suficiente información, realiza preguntas antes de dar recomendaciones. Sé profesional, claro, y técnico. No inventes detalles que el cliente no proporcionó.

            Ejemplos realistas y recomendaciones basadas en experiencia práctica son bienvenidos.
        `;
    }

    async getResponse(question: string, sessionId = "default"): Promise<string> {
        const modelName = "gemini-2.0-flash-001";

        if (!this.sessionHistory[sessionId]) {
            this.sessionHistory[sessionId] = [
                {
                    role: "user",
                    parts: [{ text: this.getSystemInstruction() }],
                }
            ];
        }

        this.sessionHistory[sessionId].push({
            role: "user",
            parts: [{ text: question }],
        });

        const contents: ChatMessage[] = this.sessionHistory[sessionId];

        const stream = await this.genAI.models.generateContentStream({
            model: modelName,
            contents,
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

        this.sessionHistory[sessionId].push({
            role: "model",
            parts: [{ text: finalText }],
        });

        console.log(`============================`);
        console.log(`\nRespuesta generada:\n${finalText}\n`);
        console.log(`============================`);

        return finalText;
    }

    resetSession(sessionId = "default") {
        this.sessionHistory[sessionId] = [];
    }
}
