// src/message/message.module.ts
import { Module } from "@nestjs/common";
import { ChatbotController } from "./controllers/message.controller";
import { ChatbotService } from "./service/message.service";

@Module({
    controllers: [ChatbotController],
    providers: [ChatbotService],
})
export class MessageModule {}
