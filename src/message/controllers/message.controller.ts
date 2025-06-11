import { Body, Controller, Post } from "@nestjs/common";
import { ChatbotService } from "../service/message.service";

@Controller('chatbot')
export class ChatbotController {
    constructor(private chatbotService: ChatbotService) {}

    @Post()
    async ask(@Body('userId') userId: string, @Body('question') question: string) {
        const answers = this.chatbotService.getResponse(question);
        return { question, answers };
    }
}
