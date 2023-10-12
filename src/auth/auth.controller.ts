import {
	Body,
	Controller,
	HttpCode,
	HttpStatus,
	Post,
	UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { TokensType } from './types';
import { AtGuard, RtGuard } from '../common/guards';
import { GetCurrentUser, GetCurrentUserId, Public } from '../common/decorators';

@Controller('auth')
export class AuthController {
	constructor(private authService: AuthService) {}

	@Public()
	@Post('local/signup')
	@HttpCode(HttpStatus.CREATED)
	signupLocal(@Body() dto: AuthDto): Promise<TokensType> {
		return this.authService.signupLocal(dto);
	}

	@Public()
	@Post('local/signin')
	@HttpCode(HttpStatus.OK)
	signinLocal(@Body() dto: AuthDto): Promise<TokensType> {
		return this.authService.signinLocal(dto);
	}

	@UseGuards(AtGuard)
	@Post('logout')
	@HttpCode(HttpStatus.OK)
	logout(@GetCurrentUserId() userId: number) {
		return this.authService.logout(userId);
	}

	@Public()
	@UseGuards(RtGuard)
	@Post('refresh')
	@HttpCode(HttpStatus.OK)
	refresh(
		@GetCurrentUserId() userId: number,
		@GetCurrentUser('refreshToken') refreshToken: string,
	) {
		return this.authService.refresh(userId, refreshToken);
	}
}
