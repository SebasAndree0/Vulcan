import { Controller, Get, Query } from '@nestjs/common';
import { ScanService } from './scan.service';

@Controller('scan')
export class ScanController {
  constructor(private readonly scanService: ScanService) {}

  @Get()
  async scan(@Query('url') url: string) {
    return this.scanService.analyzeUrl(url);
  }
}
