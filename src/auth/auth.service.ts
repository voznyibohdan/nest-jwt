import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { TokensType } from './types';

@Injectable()
export class AuthService {
	constructor(
		private prisma: PrismaService,
		private jwtService: JwtService,
	) {}

	async signupLocal(dto: AuthDto) {
		const hash = await this.hashData(dto.password);

		const newUser = await this.prisma.user.create({
			data: {
				email: dto.email,
				hash,
			},
		});

		const tokens = await this.getTokens(newUser.id, newUser.email);
		await this.updateRtHash(newUser.id, tokens.refresh_token);
		return tokens;
	}

	async signinLocal(dto: AuthDto): Promise<TokensType> {
		const user = await this.prisma.user.findUnique({
			where: {
				email: dto.email,
			},
		});

		if (!user) throw new ForbiddenException('Access denied');

		const passwordsMatches = await bcrypt.compare(dto.password, user.hash);
		if (!passwordsMatches) throw new ForbiddenException('Access denied');

		const tokens = await this.getTokens(user.id, user.email);
		await this.updateRtHash(user.id, tokens.refresh_token);
		return tokens;
	}

	async logout(userId: number) {
		await this.prisma.user.updateMany({
			where: {
				id: userId,
				hashedRt: {
					not: null,
				},
			},
			data: {
				hashedRt: null,
			},
		});
	}

	async refresh(userId: number, refreshToken: string) {
		const user = await this.prisma.user.findUnique({
			where: {
				id: userId,
			},
		});

		if (!user || !user.hashedRt) {
			throw new ForbiddenException('Access denied');
		}

		const rtMatches = bcrypt.compare(refreshToken, user.hashedRt);
		if (!rtMatches) throw new ForbiddenException('Access denied');

		const tokens = await this.getTokens(user.id, user.email);
		await this.updateRtHash(user.id, tokens.refresh_token);
		return tokens;
	}

	async updateRtHash(userId: number, refreshToken: string) {
		const hashedRt = await this.hashData(refreshToken);
		await this.prisma.user.update({
			where: {
				id: userId,
			},
			data: {
				hashedRt,
			},
		});
	}

	async hashData(data: string) {
		return await bcrypt.hash(data, 10);
	}

	async getTokens(userId: number, email: string): Promise<TokensType> {
		const accessToken = await this.jwtService.signAsync(
			{
				sub: userId,
				email: email,
			},
			{
				secret: 'AT_SECRET',
				expiresIn: 60 * 15,
			},
		);
		const refreshToken = await this.jwtService.signAsync(
			{
				sub: userId,
				email: email,
			},
			{
				secret: 'RT_SECRET',
				expiresIn: 60 * 60 * 24 * 7,
			},
		);

		return {
			access_token: accessToken,
			refresh_token: refreshToken,
		};
	}
}
