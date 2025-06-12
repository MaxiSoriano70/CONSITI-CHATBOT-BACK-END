import { Controller, Post, Body } from "@nestjs/common";
import { ChatbotService } from "../service/message.service";

@Controller('chatbot')
export class ChatbotController {
    constructor(private chatbotService: ChatbotService) {}

    @Post()
    async ask(@Body('question') question: string) {
        const answer = await this.chatbotService.getResponse(question);
        return { question, answer };
    }
}
